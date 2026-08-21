# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-21

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 625 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 625 |
| Unique family labels | 8 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 63 |
| Mirai | 25 |
| RemusStealer | 3 |
| Vidar | 3 |
| CoinMiner | 2 |
| SalatStealer | 2 |
| RustyStealer | 1 |
| AokigaharaStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 50 |
| exe | 25 |
| unknown | 10 |
| sh | 7 |
| zip | 5 |
| js | 1 |
| iso | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `c41b729e12c24b60`

| Field | Value |
|---|---|
| SHA-256 | `c41b729e12c24b609413fa253ba858249d03a61425e00a64ea95fc37f9428a64` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-21 01:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9d4f85bba3209c19464b03cd8d7606d` |
| SHA-256 | `c41b729e12c24b609413fa253ba858249d03a61425e00a64ea95fc37f9428a64` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_c41b729e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c41b729e12c24b609413fa253ba858249d03a61425e00a64ea95fc37f9428a64"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 01:52:10"
  condition:
    hash.sha256(0, filesize) == "c41b729e12c24b609413fa253ba858249d03a61425e00a64ea95fc37f9428a64"
}
```

### Sample 2: `56369be9ed5233ec`

| Field | Value |
|---|---|
| SHA-256 | `56369be9ed5233ecdead1e173e500d990725ae511910c9db5e0dccc4f1b1ae78` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 01:46:07` |
| Reporter | `Bitsight` |
| Tags | `BB3.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d81b3df81cec591cb49763098efdaa9` |
| SHA-1 | `b93a0121ec5314f1c60ef5023c054a5af4a0d263` |
| SHA-256 | `56369be9ed5233ecdead1e173e500d990725ae511910c9db5e0dccc4f1b1ae78` |
| SHA3-384 | `5c918170fd8290811172f54ffc0ca630553a9eba4d8f9d95b67777aa54e8a48701e51eb5c27852893c3d50e3332cb6b9` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T13D8523621BB064F8EEB4CB3458F18A53EA31BCC20A7557AF22D4895A7F137C69436317` |
| SSDEEP | `49152:eXv/SMkoWz6tzYXelaoSyMm1N60S4Sdb2m2:eXiMkxz66FoS5fb2` |
| ICON-DHASH | `707168f0f071f1d0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_56369be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56369be9ed5233ecdead1e173e500d990725ae511910c9db5e0dccc4f1b1ae78"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 01:46:07"
  condition:
    hash.sha256(0, filesize) == "56369be9ed5233ecdead1e173e500d990725ae511910c9db5e0dccc4f1b1ae78"
}
```

### Sample 3: `57ddb41f77ab8ac6`

| Field | Value |
|---|---|
| SHA-256 | `57ddb41f77ab8ac66ad2a8a017e7fa768e04052e68783c5683736742152a9271` |
| Family label | `unknown` |
| File name | `lilin.sh` |
| File type | `sh` |
| First seen | `2026-08-21 01:26:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab69b1c3fe5043e722f29eb1187cdda7` |
| SHA-1 | `b32e97f2f7025f0f467d2c3c1d2fb346ccda5227` |
| SHA-256 | `57ddb41f77ab8ac66ad2a8a017e7fa768e04052e68783c5683736742152a9271` |
| SHA3-384 | `820ab62801cb6a66ce6c4a5189b625f33e8f09fd7f126637825fefddee0b1b732ab39d3f686d8c99df0765a0e29686f4` |
| TLSH | `T1226162FE36A8A9920CC49D2C6A7FDC9A6471C1C82350CE66D79F7475ECACD20F065B48` |
| SSDEEP | `48:o/1fveE8Zu46U+jMH9u5DcxHY1+IWdqFI+AS:o/1fGbZu46UyMdu5Dcq1YIIc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_57ddb41f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57ddb41f77ab8ac66ad2a8a017e7fa768e04052e68783c5683736742152a9271"
    family = "unknown"
    file_name = "lilin.sh"
    file_type = "sh"
    first_seen = "2026-08-21 01:26:48"
  condition:
    hash.sha256(0, filesize) == "57ddb41f77ab8ac66ad2a8a017e7fa768e04052e68783c5683736742152a9271"
}
```

### Sample 4: `528778d697d92e7c`

| Field | Value |
|---|---|
| SHA-256 | `528778d697d92e7c239b16aa532806cc3bd70960bea7ee46156a497a5732ff12` |
| Family label | `Mirai` |
| File name | `bot.ppc` |
| File type | `elf` |
| First seen | `2026-08-21 01:07:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89e8a1743881a86008045d0219d47b62` |
| SHA-1 | `1239fdd4da2623affd710d243abdb2aca0850e9f` |
| SHA-256 | `528778d697d92e7c239b16aa532806cc3bd70960bea7ee46156a497a5732ff12` |
| SHA3-384 | `1d65f6944890fccfbf91556d9874298a9c143db4c80ec3d36a4091e2820effb118cd073fc49f6251ace0887970e7c74d` |
| TLSH | `T1D8633A02B30C0D47F5A72EF0363F2FD293DFEA8012A5E685751EEB459172A325586EC9` |
| SSDEEP | `1536:nqm/mQ1ZKW4uCrG3pDuWgjPsuEbaoujCuxnnVbT/:qm/mcIWNCraVlJuEbLulh/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_528778d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "528778d697d92e7c239b16aa532806cc3bd70960bea7ee46156a497a5732ff12"
    family = "Mirai"
    file_name = "bot.ppc"
    file_type = "elf"
    first_seen = "2026-08-21 01:07:27"
  condition:
    hash.sha256(0, filesize) == "528778d697d92e7c239b16aa532806cc3bd70960bea7ee46156a497a5732ff12"
}
```

### Sample 5: `5d66aefd528ecd9f`

| Field | Value |
|---|---|
| SHA-256 | `5d66aefd528ecd9fbd31bf6def4d9f045cbbfd237a3e5e565e9a26feaba45837` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 00:59:13` |
| Reporter | `Bitsight` |
| Tags | `a47659cdad283e9dcd10da78ff795967, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2673666c815880e365df72f845af8931` |
| SHA-1 | `25620cdbc59e173d174914458bc77d12eea3ba55` |
| SHA-256 | `5d66aefd528ecd9fbd31bf6def4d9f045cbbfd237a3e5e565e9a26feaba45837` |
| SHA3-384 | `80f9c8ed5dc8b65bf20cd0ef2c25d9561c195dc0066c12a1e826983788a07c2ac1ddd5b811d2ec3286aecc0d2d46357e` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1763633922AC651B1D499C7FC424770ADB33A7B418962BD1E3BEC0E488F57B25953E3C1` |
| SSDEEP | `98304:Yd1hcPuCxywWXozx8q80RRp19wm3jxx3bhpFZ2VNGduxQ5HSb4YDggsZLqUra+CV:Ylc2ElWX0x86z1t5hrZ2VNorBS3Dgg8Z` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_005_5d66aefd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d66aefd528ecd9fbd31bf6def4d9f045cbbfd237a3e5e565e9a26feaba45837"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 00:59:13"
  condition:
    hash.sha256(0, filesize) == "5d66aefd528ecd9fbd31bf6def4d9f045cbbfd237a3e5e565e9a26feaba45837"
}
```

### Sample 6: `bd0cc9da844d37b3`

| Field | Value |
|---|---|
| SHA-256 | `bd0cc9da844d37b34061fe0dad8aa57483401f5d9aa2b078f6bab0f05a0c93e1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 00:58:58` |
| Reporter | `Bitsight` |
| Tags | `a47659cdad283e9dcd10da78ff795967, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36fbf2399526743e0014e09c436e54f0` |
| SHA-1 | `beff0778afea3f78c855b81d66d9ff6fe4d00ae3` |
| SHA-256 | `bd0cc9da844d37b34061fe0dad8aa57483401f5d9aa2b078f6bab0f05a0c93e1` |
| SHA3-384 | `d687dcde28462a2bfde65fd9461df97fbcaa27dfc4614288a69425581e3f0897c45a4066f29769990464546059d0361b` |
| IMPHASH | `cc678ea372003a91fefb68ce6b422039` |
| TLSH | `T1E1D523D669FB58B9C4B2C3B1CF93E86D706A7B9047A49E9BBACC59108C236505C37730` |
| SSDEEP | `49152:i9QWKoAa/JTJSFRdJWwsBMzWzsjE11oC/WbCCUgtHBB7wZThBj8lAI8w89Zyo:Dx+/58RdJWBWzf411KCY1BBObj8lAI8t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_bd0cc9da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd0cc9da844d37b34061fe0dad8aa57483401f5d9aa2b078f6bab0f05a0c93e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 00:58:58"
  condition:
    hash.sha256(0, filesize) == "bd0cc9da844d37b34061fe0dad8aa57483401f5d9aa2b078f6bab0f05a0c93e1"
}
```

### Sample 7: `92ced9afa998f02b`

| Field | Value |
|---|---|
| SHA-256 | `92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126` |
| Family label | `unknown` |
| File name | `92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:58:23` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c2f218ef213a9603df366ef0f9a3d9c` |
| SHA-1 | `8409a089c458c85e87dc05b814a5dc0352a3f054` |
| SHA-256 | `92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126` |
| SHA3-384 | `6875e41ef0bccc43152e8cfe8568046bca50cf33ff88cc12295fd44bacea4f94fb06be3feb847b259b71d6dd35d33531` |
| TLSH | `T11E82A6DBECEE2729C9A033B44EEA569C35F5A48F48CBEB8647257DEC1B0855D082D904` |
| SSDEEP | `192:8TcWdZtQFEZIWveLdG+0xpMaDi0lk2IpMDgv6Cahz6VPJXdNHgCre5xfTTM42W9q:0qMIWvAapMaZk20MDqK6DNNHzrezfF2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_92ced9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126"
    family = "unknown"
    file_name = "92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:58:23"
  condition:
    hash.sha256(0, filesize) == "92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126"
}
```

### Sample 8: `9c7e0c27847e708d`

| Field | Value |
|---|---|
| SHA-256 | `9c7e0c27847e708d05d817b577a1ec06506491b8e99293c206f8b183824ca155` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-21 00:58:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4836b415b34e54e34bade1d34db3f33a` |
| SHA-1 | `0b3dcf53afc95eab016f8042e2d4478a653752f8` |
| SHA-256 | `9c7e0c27847e708d05d817b577a1ec06506491b8e99293c206f8b183824ca155` |
| SHA3-384 | `388ab253f97995632078a2a6bfa38fce82aaffd4afd01028a70f9472f6857d685bd57afc698a1e6624f253dbea6932c6` |
| TLSH | `T1D4235C6516857C24AE98C8361C7E2F0CB9AD43E6324452EE7FCB3CF68C4AA9DD10971D` |
| SSDEEP | `768:y+C9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:y+Hcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_9c7e0c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7e0c27847e708d05d817b577a1ec06506491b8e99293c206f8b183824ca155"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-21 00:58:21"
  condition:
    hash.sha256(0, filesize) == "9c7e0c27847e708d05d817b577a1ec06506491b8e99293c206f8b183824ca155"
}
```

### Sample 9: `539881a94db7eeb1`

| Field | Value |
|---|---|
| SHA-256 | `539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054` |
| Family label | `unknown` |
| File name | `539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:57:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c8d45265a11ce24fe0d4ea94343f5d2` |
| SHA-1 | `0d11e7a7abb41e87af657f7cbb40ee41f1b49021` |
| SHA-256 | `539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054` |
| SHA3-384 | `5aa598f563c9488e6c736f0496a75401020af50b657a4d7173bd14a235fc336c10ff615cf74a6958ef9019e0ea8911bc` |
| TLSH | `T1B25295D2786AF701E488D3F30C634B70E751D5896372222FCDB8AA166A55336323EBD5` |
| SSDEEP | `192:MuTzAHF6y7MBqTDU+moQ8NygqegajYtnnajtoLhW7zCw+:MLltMIE+nigqFaWnajtMWL+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_539881a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054"
    family = "unknown"
    file_name = "539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:57:35"
  condition:
    hash.sha256(0, filesize) == "539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054"
}
```

### Sample 10: `17fbce071aa53513`

| Field | Value |
|---|---|
| SHA-256 | `17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83` |
| Family label | `unknown` |
| File name | `17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:56:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `708f36fa6f5ba86ecbb81b1325b24f03` |
| SHA-1 | `326e61478f4c0f171e3d9b5f63e1adedb97aa24c` |
| SHA-256 | `17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83` |
| SHA3-384 | `bbd25ea0b7b13df73ec3ecfbbae10bc4375477a04153acbf35573679e03c0b8e352401c68992823d8f88f69df6c8322c` |
| TLSH | `T11492EB25EF8137A6CE5C037ED7B74A30A7C1698596A0C5AFC43CD2E81EC9E6E186B114` |
| SSDEEP | `384:nsKKjCz/Qr2J5pmL0fMqQyjQ5SfQuOvigyy:nsKGCw2tF5QzNv8y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_17fbce07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83"
    family = "unknown"
    file_name = "17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:56:46"
  condition:
    hash.sha256(0, filesize) == "17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83"
}
```

### Sample 11: `ae9eb4f844c3fe77`

| Field | Value |
|---|---|
| SHA-256 | `ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6` |
| Family label | `unknown` |
| File name | `ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16ae2c9cd743b5fa251133e8d63f5808` |
| SHA-1 | `b47a6736d3a8a6e373c2fb8b14e4a5a84b5335fa` |
| SHA-256 | `ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6` |
| SHA3-384 | `16db05a27b065d125a2bafd7c917ed4cd3f162a7e1156f9eef83abef384d05592131d70e1a8e036d3fd1e4aaa0aa94ed` |
| TLSH | `T1AD92D6975DC0C766C8CA0E73BC5F1668A2E19470C2E483C3A924962DAE5B77F4E8C713` |
| SSDEEP | `192:M+WODI6nTobG3m+WuibLX9cRwJzQJQ1UwddnJKsBQBt9/N6zStO+lqk:wMvcblFcRwJzQ+1ddnJX0LROY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_ae9eb4f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6"
    family = "unknown"
    file_name = "ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:33"
  condition:
    hash.sha256(0, filesize) == "ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6"
}
```

### Sample 12: `0a39e22bbed78a71`

| Field | Value |
|---|---|
| SHA-256 | `0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a` |
| Family label | `unknown` |
| File name | `0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:29` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16e8dde1f145fe52660f480e6dbc54fb` |
| SHA-1 | `7b3e70c1d60fe2157a3f14429e03a401be845b56` |
| SHA-256 | `0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a` |
| SHA3-384 | `a09915d7b611acb43652bf2f4abed4785c6bae09372378d89fae12311b87777fe89daf3cd0f7e27870d7e126d810ba5d` |
| TLSH | `T15A8296DFFD6D031EEDDC97B80E9B5EAC7CB4884F8987AAC5461464884F059AE082DC1D` |
| SSDEEP | `384:Wuk0tIZnaykeqTVSKW532ZFvqg+s8qPTQuZ:MSCaykeqTVSFBQvqg+sVPT/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_0a39e22b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a"
    family = "unknown"
    file_name = "0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:29"
  condition:
    hash.sha256(0, filesize) == "0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a"
}
```

### Sample 13: `a2566cc5c500856a`

| Field | Value |
|---|---|
| SHA-256 | `a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60` |
| Family label | `unknown` |
| File name | `a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:22` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ace13760bb9e675103787e3744607d00` |
| SHA-1 | `543e8aad4b8ee5ed967edc8ae7c5120bad88892c` |
| SHA-256 | `a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60` |
| SHA3-384 | `63744f646690ca893954106782d85760490b6b832eac00fb5aa7e65e8eb9b2132f7e696a642332b40f9718b0724c4847` |
| TLSH | `T1B68296DFFD6D031EEDDC97B80E9B5EAC7CB4884F8987AAC5461464884F059AE082DC1D` |
| SSDEEP | `384:Yukv5IZnaykeqTVSKW532ZFvqg+s8qPTQuZ:GhCaykeqTVSFBQvqg+sVPT/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_a2566cc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60"
    family = "unknown"
    file_name = "a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:22"
  condition:
    hash.sha256(0, filesize) == "a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60"
}
```

### Sample 14: `6a85c51a34bc1007`

| Field | Value |
|---|---|
| SHA-256 | `6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5` |
| Family label | `unknown` |
| File name | `6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:18` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf5da3944ef09f3c530ef6e980b585b5` |
| SHA-1 | `564108b31b5d3e850102133572da24d69ec42ea2` |
| SHA-256 | `6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5` |
| SHA3-384 | `535c4d9ca695e90016c2d404711f5b80a46fc438ee2c76d84771216c5a95e9f51ceee9dc0df2bc06b05f3cce82843a18` |
| TLSH | `T17C62D76361524703CCD50F3896A66F709B206A3C427D2ED7C9587894BBCB1790D3BAEA` |
| SSDEEP | `384:/nEGhMFMLOFBwFWb7kZ3CCzVZcyetEThNY3jQhk:PEGhMFbFqpZ31VZ0yhNJk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_6a85c51a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5"
    family = "unknown"
    file_name = "6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:18"
  condition:
    hash.sha256(0, filesize) == "6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5"
}
```

### Sample 15: `5558a2bb032ea66c`

| Field | Value |
|---|---|
| SHA-256 | `5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f` |
| Family label | `unknown` |
| File name | `5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5067b8c63e7549f82ed2d90e2e28c151` |
| SHA-1 | `2ef4ce5fa839b78c3328e726aff467d77cfb62e8` |
| SHA-256 | `5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f` |
| SHA3-384 | `41fad9f2eef994185383431b9bb835a0a9829003911952a43403b45bcf7fa25a98ba01122b3ee48909fc66acf4dd89b5` |
| TLSH | `T1E07275C3E211E7A3FD838FF95C9F0AB5A22784004545A982DD0C98F79E4995F351DC9B` |
| SSDEEP | `192:f5cduWvTwGhXqWVNVleAwcCtvEzoIsbkEdNbASMbWMc:fO8SFjly9trfbA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_5558a2bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f"
    family = "unknown"
    file_name = "5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:14"
  condition:
    hash.sha256(0, filesize) == "5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f"
}
```

### Sample 16: `71b6be340eb467de`

| Field | Value |
|---|---|
| SHA-256 | `71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070` |
| Family label | `unknown` |
| File name | `71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7652b773236fb8bac4537d662de6f1b0` |
| SHA-1 | `1ad3ae45702c9dca73e60d69d19603684b938d3b` |
| SHA-256 | `71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070` |
| SHA3-384 | `4694a87a5d05f762426482f1599ad76e1fb2ed0da3968833ca2ea6cb483f067aa54f92a5c18237ed915f3984497fbad3` |
| TLSH | `T1A5A22FB3D34481B7D99FCAF64EE2C23C8B490820865C5B2FD9D8D418167EA4C97E2F64` |
| SSDEEP | `384:pFlyM13CfkETDV9zpHgdFVULrUBj7aJT4XiyTGzULJGp:pFlyMbEHdETPJs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_71b6be34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070"
    family = "unknown"
    file_name = "71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:08"
  condition:
    hash.sha256(0, filesize) == "71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070"
}
```

### Sample 17: `a84943487aa16c44`

| Field | Value |
|---|---|
| SHA-256 | `a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199` |
| Family label | `unknown` |
| File name | `a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5babeccb46e4059e1372361d0d251083` |
| SHA-1 | `03e9605ef0838d92f1e95e57a60d3472a60cab23` |
| SHA-256 | `a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199` |
| SHA3-384 | `f28312afdb7cdb5246f443a1ba6d55b96e19381294b97450cf24a8df28d4af4d7e0fbabe55fd152eb3d163d8d9be3f21` |
| TLSH | `T1EC8287C3C199F3AAE9924BFDEC4E8B79622784048544A186DD1CD8F7DF8A52F302DD19` |
| SSDEEP | `192:fA7G/CxbTgYuV2IBknYcX2J71n3pVCUvAqBAspkJMz+DUZw+1i/89RXJo03Nu6zb:fb6E6Z47JLX6mn/w4FC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_a8494348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199"
    family = "unknown"
    file_name = "a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:04"
  condition:
    hash.sha256(0, filesize) == "a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199"
}
```

### Sample 18: `815596f7c078ce86`

| Field | Value |
|---|---|
| SHA-256 | `815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d` |
| Family label | `unknown` |
| File name | `815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d.elf` |
| File type | `elf` |
| First seen | `2026-08-21 00:53:00` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec38c017f6c736567088e1286862bea1` |
| SHA-1 | `2e505f0240586a4b1ebd9bba3ab2b96ed159819e` |
| SHA-256 | `815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d` |
| SHA3-384 | `d3fb5201764f96f117c8546d7cd32857dabe39ba14a96a4074659729bffbc4505a3087b00d7eb147cc5a938e85a287e3` |
| TLSH | `T1DD5274437702971ECEAD17F94DAB057132BA1A1C4701636A979CBAE4A444F2E873F3D2` |
| SSDEEP | `192:MlA6aTG1hesXzHlb5+6pw0v4xQVarF06nCR73/32BAxvb9X:MlA6TlbU2lQxQVq06nYz/G8V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_815596f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d"
    family = "unknown"
    file_name = "815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:00"
  condition:
    hash.sha256(0, filesize) == "815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d"
}
```

### Sample 19: `8c7c585913713349`

| Field | Value |
|---|---|
| SHA-256 | `8c7c585913713349d3ffe23cc4f5180f55cfbc01b538200763a86dcf63e2d2bc` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-21 00:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c085cf2b73322c5f0113c97d33706552` |
| SHA-256 | `8c7c585913713349d3ffe23cc4f5180f55cfbc01b538200763a86dcf63e2d2bc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_8c7c5859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7c585913713349d3ffe23cc4f5180f55cfbc01b538200763a86dcf63e2d2bc"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 00:52:11"
  condition:
    hash.sha256(0, filesize) == "8c7c585913713349d3ffe23cc4f5180f55cfbc01b538200763a86dcf63e2d2bc"
}
```

### Sample 20: `559c37e58a67f08b`

| Field | Value |
|---|---|
| SHA-256 | `559c37e58a67f08b55c3436e59f906246a1d2d467149a41bddc14818f61b573a` |
| Family label | `unknown` |
| File name | `svvhost.exe` |
| File type | `exe` |
| First seen | `2026-08-21 00:51:21` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cda3fcd3db4b12ed675809e25a908520` |
| SHA-1 | `af923151854111c71b515cc156e585d6a3705821` |
| SHA-256 | `559c37e58a67f08b55c3436e59f906246a1d2d467149a41bddc14818f61b573a` |
| SHA3-384 | `61fd7dbc5ed34b45acb3844e6fa82c3d7a667181ce4d3d775966d3456af82e83ae476a943dd2f27f2ef9334d476d903c` |
| IMPHASH | `57f518ff8223b8b7cbb14a0e738c23d1` |
| TLSH | `T120F33A17725020E9E433C074CD969637F7B2386423201AEF6568EB752F226E2BF7A355` |
| SSDEEP | `3072:OTjZXvqdwANWM5yykJNd4Jjn5k798+0EVGj0gH8iay:OTxvqSANWwkJNSp5098+0EwR` |
| ICON-DHASH | `3cfcdcdcf4f4f4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_559c37e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "559c37e58a67f08b55c3436e59f906246a1d2d467149a41bddc14818f61b573a"
    family = "unknown"
    file_name = "svvhost.exe"
    file_type = "exe"
    first_seen = "2026-08-21 00:51:21"
  condition:
    hash.sha256(0, filesize) == "559c37e58a67f08b55c3436e59f906246a1d2d467149a41bddc14818f61b573a"
}
```

### Sample 21: `6162dd763b88e4ca`

| Field | Value |
|---|---|
| SHA-256 | `6162dd763b88e4ca3325960d7870f3eea68cefcc0ccbb97a02f32d00f34c399c` |
| Family label | `unknown` |
| File name | `ReflectiveHVNC64.dll` |
| File type | `exe` |
| First seen | `2026-08-21 00:51:19` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3d10b68ee4cc6b0279110ac18704eb0` |
| SHA-1 | `b3e00fe25298bc64aeea0bfbfcaaf4bd613675a0` |
| SHA-256 | `6162dd763b88e4ca3325960d7870f3eea68cefcc0ccbb97a02f32d00f34c399c` |
| SHA3-384 | `ebcc31c00cda25cbf83c49c09835b3598b372cdbef3ce268fa9a51eb9d9530eaf28127cfb00452f295b59e8f3a3e61dc` |
| IMPHASH | `893117acd2900217e1ea9ec8648addbc` |
| TLSH | `T109F32907B65451AAE533C034CA979633F7B3384823201ADF6164EA752F237E2BB7A355` |
| SSDEEP | `3072:K9MZ6wv6Mb9i4y3EHLe+WGhk+AvZ8Z8mXspkORTm:K93whI/se+PEZ8ZheTm` |
| ICON-DHASH | `3cfcdcdcf4f4f4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_6162dd76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6162dd763b88e4ca3325960d7870f3eea68cefcc0ccbb97a02f32d00f34c399c"
    family = "unknown"
    file_name = "ReflectiveHVNC64.dll"
    file_type = "exe"
    first_seen = "2026-08-21 00:51:19"
  condition:
    hash.sha256(0, filesize) == "6162dd763b88e4ca3325960d7870f3eea68cefcc0ccbb97a02f32d00f34c399c"
}
```

### Sample 22: `c1634bbe012d27a8`

| Field | Value |
|---|---|
| SHA-256 | `c1634bbe012d27a8a8d6815f750b41c36c5249b79953d5fec6f36e21de1381e4` |
| Family label | `unknown` |
| File name | `HVNC64.dll` |
| File type | `exe` |
| First seen | `2026-08-21 00:51:17` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fcfd046f62d40f4a95dff00bea95931` |
| SHA-1 | `b83d8fbb979bdbfa0b88dfa25be770f4d28ad40a` |
| SHA-256 | `c1634bbe012d27a8a8d6815f750b41c36c5249b79953d5fec6f36e21de1381e4` |
| SHA3-384 | `e477d0b3cef807cb71eb9dd237571813f16d3fef43cc65a6e552fc7e7ae7efbd1eed12b947a8d9adc4b5bf5d60fff18b` |
| IMPHASH | `714627db03650ab1afc83cd06cac881a` |
| TLSH | `T1FBF32907B65450AAE537C035CE979632E7B2384427201AEF6168EB752F337D2BB7A344` |
| SSDEEP | `3072:J9DZz8QkzTloiFx63VUfWUp8G7x8oPGXf3mJ3odLwZD+p1:J918dTllxIUfWYx8ouXfmCENC` |
| ICON-DHASH | `3cfcdcdcf4f4f4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_c1634bbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1634bbe012d27a8a8d6815f750b41c36c5249b79953d5fec6f36e21de1381e4"
    family = "unknown"
    file_name = "HVNC64.dll"
    file_type = "exe"
    first_seen = "2026-08-21 00:51:17"
  condition:
    hash.sha256(0, filesize) == "c1634bbe012d27a8a8d6815f750b41c36c5249b79953d5fec6f36e21de1381e4"
}
```

### Sample 23: `25f6183c81502416`

| Field | Value |
|---|---|
| SHA-256 | `25f6183c81502416d8a5a49457026e69e5e6c31d20d6b3052a1ef56c0c040285` |
| Family label | `unknown` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `094f0c12b69e2782b6a0d54e22d67f58` |
| SHA-1 | `94a4132b28d383c42bd71480ccd883e3d530cc77` |
| SHA-256 | `25f6183c81502416d8a5a49457026e69e5e6c31d20d6b3052a1ef56c0c040285` |
| SHA3-384 | `6d6c8f1107cacece049fcb8320074bf227d19b0d91e424b49be8eb5f04bd8c7ee0ba9f3ac0663dc1ddc385b6aa9f523a` |
| TLSH | `T1D572F861EE89C2B8D0AC197C1017AB38AB82950A4689F787C83F9C223F1535F6DF5316` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:H+ZoDFRTobGj8cuoBTGccayw7GrzU+xNAE2iTE:scFebq8cuQbynr7xNhL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_25f6183c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f6183c81502416d8a5a49457026e69e5e6c31d20d6b3052a1ef56c0c040285"
    family = "unknown"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:45"
  condition:
    hash.sha256(0, filesize) == "25f6183c81502416d8a5a49457026e69e5e6c31d20d6b3052a1ef56c0c040285"
}
```

### Sample 24: `b246f4efb094d215`

| Field | Value |
|---|---|
| SHA-256 | `b246f4efb094d21540a24731186b88e997f88c775416a2ce96b4c54c7ee9d940` |
| Family label | `unknown` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c76f5598ffc445f0d425d2cdd0cb701` |
| SHA-1 | `1de1da749293f0ef4e8b8440de88f4099bca19d9` |
| SHA-256 | `b246f4efb094d21540a24731186b88e997f88c775416a2ce96b4c54c7ee9d940` |
| SHA3-384 | `d9d91e0217d0c9fffd18af739295b62674b576ce49963162c499b88fecdbea54e4375d5c1d86be3bb65c20c718f59294` |
| TLSH | `T19D42D642BCB1B747CAC007764F3BE78C3B92E136C7D5F78A056A566D2E2E0162E0A645` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:1/+K63u+uEJR/QXMeMb9qT5xxDEFKN5i2laGr6iDHVElJyjvUu/:1Me+uEJFZeKekiY7GrzHVEOz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_b246f4ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b246f4efb094d21540a24731186b88e997f88c775416a2ce96b4c54c7ee9d940"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:43"
  condition:
    hash.sha256(0, filesize) == "b246f4efb094d21540a24731186b88e997f88c775416a2ce96b4c54c7ee9d940"
}
```

### Sample 25: `1d1b10444e55e9b7`

| Field | Value |
|---|---|
| SHA-256 | `1d1b10444e55e9b7a0b0aa8ce7bcc3d82e818246b096a954c49ea7750e478dd5` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e71f7d5feacdce29d63d37463542eb2` |
| SHA-1 | `1d738a2122351b685e53a95d2813f3feb475b7b7` |
| SHA-256 | `1d1b10444e55e9b7a0b0aa8ce7bcc3d82e818246b096a954c49ea7750e478dd5` |
| SHA3-384 | `4e9caabfd047048ad32d6e7099fc5dc311447be1dd61f4258ef6443bb27a0f65a4d7aac4733ec56d057148fccfb54c7f` |
| TLSH | `T18A6272496A748FFEF6A6C7B8C767CF70829421A243D2C6DED22CF0020C54719AC1E768` |
| TELFHASH | `t175e07d04fdbf4d3355e31df4e83c47705405b20801604712afb4a0d4843b124b252e7d` |
| SSDEEP | `192:NenRPhNtYTWE0IJUA7VXHi8l/25E+jqDmZw3Ll6Yt:YRpYWqUA53i8S7ZwoYt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_1d1b1044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d1b10444e55e9b7a0b0aa8ce7bcc3d82e818246b096a954c49ea7750e478dd5"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:42"
  condition:
    hash.sha256(0, filesize) == "1d1b10444e55e9b7a0b0aa8ce7bcc3d82e818246b096a954c49ea7750e478dd5"
}
```

### Sample 26: `ce890f43a6545fb0`

| Field | Value |
|---|---|
| SHA-256 | `ce890f43a6545fb0dbd39193364960bb5107b069e8d7fa6e1e31a238ec631d32` |
| Family label | `unknown` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16950ec1d69ca43e45822ecfa7a2d8bf` |
| SHA-1 | `d17edd20aab875efa4731d775c7a852f49866b72` |
| SHA-256 | `ce890f43a6545fb0dbd39193364960bb5107b069e8d7fa6e1e31a238ec631d32` |
| SHA3-384 | `1732f0c06e286e50b2bd4f3436013bdc4d8ca370717094f818b7de7347b75683b85fa628adb52d7c1f96b4db6d01feea` |
| TLSH | `T19942B7C3E4919A12DAC08BB85F3E9BCD3567D234F69BBB4FC4099350186F1494E1E983` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:RNMjnaBtmNlHDJ+82Wd3Vg6n7a6enSgkhZTDZwjP4kTgc1SAlI:7MNlDAB6FZ7a6nhzwkk1Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_ce890f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce890f43a6545fb0dbd39193364960bb5107b069e8d7fa6e1e31a238ec631d32"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:41"
  condition:
    hash.sha256(0, filesize) == "ce890f43a6545fb0dbd39193364960bb5107b069e8d7fa6e1e31a238ec631d32"
}
```

### Sample 27: `662a233dbc7d95cc`

| Field | Value |
|---|---|
| SHA-256 | `662a233dbc7d95cc6612526d0f9e43390a95eb4870cd50242b2e64ba2a589202` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e144da1c70f09ac91a7ff7985b4b8b6` |
| SHA-1 | `fbfe9a03e174ba8068c64deaf0f14ddafcd1bb74` |
| SHA-256 | `662a233dbc7d95cc6612526d0f9e43390a95eb4870cd50242b2e64ba2a589202` |
| SHA3-384 | `c9f2bbcb507c3972e4a084e9ccdea7bb0ad7fd28d67d3604ed263dd12526d68bc7d3043184357c207f036f2d875ef107` |
| TLSH | `T1AC4208D07826CAFAC945C2344D4F7B3D09E0C409BB35AF9BEB28FE9DEA1F5491149244` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:f2d/Zj5uNTChzMAG8YWnkTwztvvrmP596v0gXD4x5nltI+UCqrdWQ:fO5uuMZ8pi8ns2XDmI+UCqV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_662a233d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "662a233dbc7d95cc6612526d0f9e43390a95eb4870cd50242b2e64ba2a589202"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:39"
  condition:
    hash.sha256(0, filesize) == "662a233dbc7d95cc6612526d0f9e43390a95eb4870cd50242b2e64ba2a589202"
}
```

### Sample 28: `c150ee2cfafe6d90`

| Field | Value |
|---|---|
| SHA-256 | `c150ee2cfafe6d907ca5b325cf0282a7516a172c6326d730bd4ee8faa716e000` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9646accdea9896a74e3cbb5f608c353e` |
| SHA-1 | `5cc00d394a9072316de5030d25dab35939eb3ac8` |
| SHA-256 | `c150ee2cfafe6d907ca5b325cf0282a7516a172c6326d730bd4ee8faa716e000` |
| SHA3-384 | `0f17481f05b242a1ed2128a795c19ba8649e218e25f0b3bc0d823bec203dea1df850c0c4dd733079b7ff5d9d827b6f0d` |
| TLSH | `T1FF728547AF200D7BED07CEB78A9B171640CE9537E1D5BF27A528E940B6091AB0CE7C58` |
| TELFHASH | `t175e07d04fdbf4d3355e31df4e83c47705405b20801604712afb4a0d4843b124b252e7d` |
| SSDEEP | `384:iUTX10FAq//YSGR4s2xtFwu/CmgmPtv1EBEU:iUj10FA6/wRUtVCmgmPe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_c150ee2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c150ee2cfafe6d907ca5b325cf0282a7516a172c6326d730bd4ee8faa716e000"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:38"
  condition:
    hash.sha256(0, filesize) == "c150ee2cfafe6d907ca5b325cf0282a7516a172c6326d730bd4ee8faa716e000"
}
```

### Sample 29: `ee364d83f7c7ae69`

| Field | Value |
|---|---|
| SHA-256 | `ee364d83f7c7ae6934283025b999c9b11e83fef527217b879fbf54bbe998b692` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `689a8e6559b541be5d6317f875681e5a` |
| SHA-1 | `7a3af5349f354543115baf32baa33a08bed919f6` |
| SHA-256 | `ee364d83f7c7ae6934283025b999c9b11e83fef527217b879fbf54bbe998b692` |
| SHA3-384 | `fc1b5913657122b2d20496d3dc4f7f018ada7c4302195e9854cce15790a2e893b9fa9655f8c101bb8d4ba05d3fa5bf32` |
| TLSH | `T19432F929BB1E0142CD813EB0C75B33D147DA75C062646F8BE1594225EBB2A1A5E3B3DD` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:W3Z0QbTrHyJf34O5oZyhaCC7xMmPuWP1hE8SjsQf39ltBLuiDJ0+Lqf:WN+JfoO5oZyg7YM+G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_ee364d83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee364d83f7c7ae6934283025b999c9b11e83fef527217b879fbf54bbe998b692"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:37"
  condition:
    hash.sha256(0, filesize) == "ee364d83f7c7ae6934283025b999c9b11e83fef527217b879fbf54bbe998b692"
}
```

### Sample 30: `1385c0859e91a4a8`

| Field | Value |
|---|---|
| SHA-256 | `1385c0859e91a4a8492fbc4de56d0c7ea8dbdea77c8c776aaa1ec705dfa96b90` |
| Family label | `unknown` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `debc40a39f6a9b0b95f4b310859426cb` |
| SHA-1 | `06dc187b6cfa65427ff2d9697b47edc4b9b9e296` |
| SHA-256 | `1385c0859e91a4a8492fbc4de56d0c7ea8dbdea77c8c776aaa1ec705dfa96b90` |
| SHA3-384 | `93f59a44d903de993ce541bbdb96ed40910d62df4d2b4184605cfef71a0fcc54137309bfe8554da49da7d386e29037f8` |
| TLSH | `T18332D60306B6D917C8C0133190B74772B9E6AF555BAADB6FFC2D480A5CA63902E3F384` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `96:90o1MgTc1Pdl9ozwbKMigtrF1PTr+W803gU0ReZNYuOf5Zw3jkrBU1vnrMW9livD:2TgOy4igZ3q0P5OhmzkOTMWzenD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_1385c085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1385c0859e91a4a8492fbc4de56d0c7ea8dbdea77c8c776aaa1ec705dfa96b90"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:36"
  condition:
    hash.sha256(0, filesize) == "1385c0859e91a4a8492fbc4de56d0c7ea8dbdea77c8c776aaa1ec705dfa96b90"
}
```

### Sample 31: `7681a07ca6e157f8`

| Field | Value |
|---|---|
| SHA-256 | `7681a07ca6e157f8066d8eef5d53afaaedf965aecc43bfade7af4edc5bbe21fd` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c30a4291939f136784c89154a6240b49` |
| SHA-1 | `a2690981fdce81b1483c95d35bb8667a50a84e35` |
| SHA-256 | `7681a07ca6e157f8066d8eef5d53afaaedf965aecc43bfade7af4edc5bbe21fd` |
| SHA3-384 | `b44b6d410b16869aaaa479d34d164b44bd56827ab43551e079c808fb0a88c5aceaee46c11298d0e95c4e57c9160d6a4b` |
| TLSH | `T1B752B436AF40417CCC8444F88C8B577194E2A4C3EB69EB87C358FAA8791574D5A1E6BC` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:G27TGDPCrXJAviauTV0wsaUwqEVgW3s87zX7gaVL:kDPCrXeviV0wsaUlop7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_7681a07c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7681a07ca6e157f8066d8eef5d53afaaedf965aecc43bfade7af4edc5bbe21fd"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:34"
  condition:
    hash.sha256(0, filesize) == "7681a07ca6e157f8066d8eef5d53afaaedf965aecc43bfade7af4edc5bbe21fd"
}
```

### Sample 32: `df39ed227704f9d6`

| Field | Value |
|---|---|
| SHA-256 | `df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48` |
| Family label | `unknown` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4235a3b77678f7293ffd44a6c92b3a0` |
| SHA-1 | `8228f2e3f33c54a6ba6a96216541e96325f00870` |
| SHA-256 | `df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48` |
| SHA3-384 | `d126f6b0108e576892df34a42c29d12d8540ba649a3d2c46faba9a5e8297b7b16ed90c310d32c4388ab4079a73abc9bb` |
| TLSH | `T17C42D642BCB1B747CAC007764F3BE78C3BD2E135C7D5F78A056A566D2E2E0162E0A645` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:3/+K63u+uEJR/QXDMb9qT5xxDEFKN5i2laGr6iDHVElJyjvUu/:3Me+uEJFsKekiY7GrzHVEOz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_df39ed22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:33"
  condition:
    hash.sha256(0, filesize) == "df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48"
}
```

### Sample 33: `f7c770b11a493248`

| Field | Value |
|---|---|
| SHA-256 | `f7c770b11a493248931a66044ffd4e7e43204e15d3ab29b0f08cd6f74606c6bf` |
| Family label | `unknown` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35cc3076c6ee744f16b5738afc7bb3e5` |
| SHA-1 | `76c376eba8532a61dd9f7da1bdd084d4e471c77d` |
| SHA-256 | `f7c770b11a493248931a66044ffd4e7e43204e15d3ab29b0f08cd6f74606c6bf` |
| SHA3-384 | `ecd9f684cb6b6ddcce2d384b4f7839b74d394d9b4637a2bd39fed660b05806a261b4fda635d37abb82262eef5f7da5d9` |
| TLSH | `T1AD22C70F1E10292EE8D4117CAA1BC78594C99E61C246630F73E99BD69CB725C7F7B2C8` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:VKTVu/E0nJpvaFVADvdRd3JGk07p2kSl7Io:V7E0nHaeB3JN0ilP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_f7c770b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7c770b11a493248931a66044ffd4e7e43204e15d3ab29b0f08cd6f74606c6bf"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:32"
  condition:
    hash.sha256(0, filesize) == "f7c770b11a493248931a66044ffd4e7e43204e15d3ab29b0f08cd6f74606c6bf"
}
```

### Sample 34: `3b382773c6d6af85`

| Field | Value |
|---|---|
| SHA-256 | `3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063` |
| Family label | `unknown` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7854fc75b1ae0a8f4a4731c0b5dfd2b` |
| SHA-1 | `172551132ca8f825b7cac7e231fdb1e386174f61` |
| SHA-256 | `3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063` |
| SHA3-384 | `e73acb83a7712e3fc1f4d7703464be970ed9451ed0012d5d90b64a74e1a615bf2c1c536b0759db273a90715fdbdeb3d6` |
| TLSH | `T1FD52B8039B12CA75CAA011B988474F301D51CC03AE5AEF1BF668F9F9756128DA11EF79` |
| TELFHASH | `t156d02e00fdbb0e2628e31874e82c02ace002920401a087346f68e0d1843b224a222b6e` |
| SSDEEP | `192:fgLGMxbTgY9UMWu5X+ERXmJDRjyaXL0BtebQ6vIsxId0mfO9LU2vhUv/L++rC:fAfUMWu5uumJdum06vzhmKL9vhU7Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_3b382773
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063"
    family = "unknown"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:30"
  condition:
    hash.sha256(0, filesize) == "3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063"
}
```

### Sample 35: `30db2a6a5946a66c`

| Field | Value |
|---|---|
| SHA-256 | `30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-21 00:18:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3c2b965608f75116e7e58a81f564f3e` |
| SHA-1 | `7d240ccc1cf36d6b679fc116544700a40223dd01` |
| SHA-256 | `30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2` |
| SHA3-384 | `4f09c2fabdbd8266c09c03f13f47a785fc3babeeed5a6c18090875413287465b6838ef17ff29f0134f306cdb3ecccfaf` |
| TLSH | `T12342C641AE23CAB5DDE412358C97573C0DC084027A37FF4BD238D9BDA839946969ABB4` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:fgFtdyfTa30Vhk7huDAz4wYRmZj4UDmoJ5BHokxIEY55t3e/C8Qm:fSyG0Vhk1uDA+kDmeHLx055tT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_30db2a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:29"
  condition:
    hash.sha256(0, filesize) == "30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2"
}
```

### Sample 36: `1647c36ad4a2f947`

| Field | Value |
|---|---|
| SHA-256 | `1647c36ad4a2f94705eebbd4aff38a6541b9051abf35deb8a8947845b23e2c58` |
| Family label | `unknown` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-21 00:15:26` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `614ce22ae7a94d72633c2168b3e723ba` |
| SHA-1 | `98b33267b6304544e5ab2a368f8e438e65b6a0ea` |
| SHA-256 | `1647c36ad4a2f94705eebbd4aff38a6541b9051abf35deb8a8947845b23e2c58` |
| SHA3-384 | `1821941b328fd25044135eb1847e273ef47a33c166ad73e0de994a3deceb4653b98036f34317844f2dff1b97c378d7ce` |
| TLSH | `T1CD72A583A5919913CAC08BB85B7F9B8D3663D225E28BB70F850D93902C5F14D4F5FA87` |
| TELFHASH | `t1a9d0a700fdb60e2a69e31874e96c47646016921511a047655f64e0d4953f1246211ead` |
| SSDEEP | `192:gpAhrTBtmNlHDJ+82Wd3Vg6n7a6enSgkhZTDZwjP4kTgc1SAlNe4UTuwEIpu:JMNlDAB6FZ7a6nhzwkk1QKejHf4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_1647c36a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1647c36ad4a2f94705eebbd4aff38a6541b9051abf35deb8a8947845b23e2c58"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-21 00:15:26"
  condition:
    hash.sha256(0, filesize) == "1647c36ad4a2f94705eebbd4aff38a6541b9051abf35deb8a8947845b23e2c58"
}
```

### Sample 37: `7e788bd6e7940f7c`

| Field | Value |
|---|---|
| SHA-256 | `7e788bd6e7940f7c57dbfd94da87a48b4f36fad48c04a8bb1ba82971317f9023` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 00:03:30` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX1.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7543bf36d409d596e20b6d1b78e20d73` |
| SHA-1 | `d39276743f7d7c42099651e92611a8908bbcef20` |
| SHA-256 | `7e788bd6e7940f7c57dbfd94da87a48b4f36fad48c04a8bb1ba82971317f9023` |
| SHA3-384 | `4e84e648ae6a9a5a8fdb2b2bbf02d34c8deddb9c3c0ffb08123ebb4d240ceb5c2abf87730adf767cec998fcbad131548` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T165465A03BCA505A9C0AAA734C9B78652BB757C88873133D72E50BA383F76BD06D79714` |
| SSDEEP | `98304:3m6wpM6yULIPtqPA/QmPomMBxfbP8tlX7:mpM6yULIPtqPA/QmPomMBxf0Z7` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_037_7e788bd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e788bd6e7940f7c57dbfd94da87a48b4f36fad48c04a8bb1ba82971317f9023"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 00:03:30"
  condition:
    hash.sha256(0, filesize) == "7e788bd6e7940f7c57dbfd94da87a48b4f36fad48c04a8bb1ba82971317f9023"
}
```

### Sample 38: `30ef59b648d3e243`

| Field | Value |
|---|---|
| SHA-256 | `30ef59b648d3e243f641140930a6520f2d6b950defdfb9f41d75953394d88fde` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-20 23:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e28fe72752d6dd3d6f55a25d97a4883d` |
| SHA-256 | `30ef59b648d3e243f641140930a6520f2d6b950defdfb9f41d75953394d88fde` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_30ef59b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30ef59b648d3e243f641140930a6520f2d6b950defdfb9f41d75953394d88fde"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 23:52:11"
  condition:
    hash.sha256(0, filesize) == "30ef59b648d3e243f641140930a6520f2d6b950defdfb9f41d75953394d88fde"
}
```

### Sample 39: `1337ed6fe9c6205b`

| Field | Value |
|---|---|
| SHA-256 | `1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Generic.Dacic.21301.F2A0AC0E.15689265` |
| File type | `exe` |
| First seen | `2026-08-20 23:51:52` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae562ddc495a05b75fe617e4feec91bf` |
| SHA-1 | `bf444dcd65b2b22146896f79128bf85a3e16bdb0` |
| SHA-256 | `1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb` |
| SHA3-384 | `e01ff42ebfab55a62aeb6af48285ac51c69aaac8738110cd6cf93a40f52b9d8eaa634c39feaefa1bf87f7135cce413d4` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T173D40106BBBA65FCE26789B5C9650A62F7373A1503509F2F1360C671BF136A07D28B31` |
| SSDEEP | `12288:yVrlYPmBiF9LVWqe2rOQhe0Oxm5t5TNTv3aog6pwIB:5PmQF9y2rPe0Oo5t5pTvK5nIB` |
| ICON-DHASH | `e892a44a2ab6ccf0` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_039_1337ed6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Generic.Dacic.21301.F2A0AC0E.15689265"
    file_type = "exe"
    first_seen = "2026-08-20 23:51:52"
  condition:
    hash.sha256(0, filesize) == "1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb"
}
```

### Sample 40: `b3cb247a4848f22c`

| Field | Value |
|---|---|
| SHA-256 | `b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971` |
| Family label | `unknown` |
| File name | `b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971.exe` |
| File type | `exe` |
| First seen | `2026-08-20 23:26:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `228684653e85f61504a8e9dcf8410c43` |
| SHA-1 | `c394e43f8c43d4005a99dfa6027f20342eb358c8` |
| SHA-256 | `b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971` |
| SHA3-384 | `6f2d7f156f4a155eda72e007dddc4187af4c0597dd240c33a73f7e51089ab60787f7d9e4a7cca2886580b7db455deb8a` |
| IMPHASH | `b8048b8957358587b4fda264349e8f60` |
| TLSH | `T12AD523DAB9B619F4D836C7B28F92F0AC702D7B8587B19C6B318C54508D63A9C2C353B1` |
| SSDEEP | `49152:azNXUgS3J/lvJVHD6OFEYvKcFYOXKu9I+tC/wui6MVmcL7s7j10av6v0Uv9x:wJO3JNvJVvEYyxOXJ9I+E6OSv0aL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_b3cb247a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971"
    family = "unknown"
    file_name = "b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971.exe"
    file_type = "exe"
    first_seen = "2026-08-20 23:26:41"
  condition:
    hash.sha256(0, filesize) == "b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971"
}
```

### Sample 41: `44e7af5e5bd2b34b`

| Field | Value |
|---|---|
| SHA-256 | `44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389` |
| Family label | `unknown` |
| File name | `44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389.exe` |
| File type | `exe` |
| First seen | `2026-08-20 23:21:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e3b12fa293212cd6d3e404c602f18ff` |
| SHA-1 | `1c8d9fc62dd9ce2469bb0c5b07811939ef2712e2` |
| SHA-256 | `44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389` |
| SHA3-384 | `8d248145beed5c42e4974bba83c594f765d3d9c10f0892bb0c28e3519da02ae30ca421105988800b7bd30a725c9de10a` |
| IMPHASH | `24e8765fd838d429e6f908cdeb96c2d6` |
| TLSH | `T175D5228AFCF20575E837C3B68683203CB13E77508B695D9735CDAB202E629546C367B9` |
| SSDEEP | `49152:ttlxc2EiFvXXgfp37b+19MPqGw1PZpNr3v/wXL7hoXqUvlekd3+Soz3VlV513K3C:BKOnMrHw1PnNr3vYXL7WqUIkd3+d3K3O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_44e7af5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389"
    family = "unknown"
    file_name = "44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389.exe"
    file_type = "exe"
    first_seen = "2026-08-20 23:21:11"
  condition:
    hash.sha256(0, filesize) == "44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389"
}
```

### Sample 42: `c4267c66c433f9fe`

| Field | Value |
|---|---|
| SHA-256 | `c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6` |
| Family label | `unknown` |
| File name | `c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6.js` |
| File type | `js` |
| First seen | `2026-08-20 23:12:40` |
| Reporter | `johnk3r` |
| Tags | `js, serverng-online` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b986bcda051d0b6ddc4f501e26922a02` |
| SHA-1 | `6ea09045a1a859a251e448331988bd00b0b07132` |
| SHA-256 | `c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6` |
| SHA3-384 | `40a26f55de38bbc7c51bdf24e72e09dff817b8be17a79c15fe515fd729b4c07a9593cd59003ffc90be47b45117c58cb9` |
| TLSH | `T11EF43AF4B991B8E43E8EEB93E798F4EDD0A335DBBACE21153018876625700D1C6C5CA5` |
| SSDEEP | `12288:3XOAKJeAudC83sbVgDKiplQFwsW3jrLaB3Wxjm/W3gdT00wWy6QmV83S/7Oozvur:3XO2AdPnFVKxxjGWnC6+qwS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_c4267c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6"
    family = "unknown"
    file_name = "c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6.js"
    file_type = "js"
    first_seen = "2026-08-20 23:12:40"
  condition:
    hash.sha256(0, filesize) == "c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6"
}
```

### Sample 43: `d405153884a919e6`

| Field | Value |
|---|---|
| SHA-256 | `d405153884a919e627f5682af122341b19007c5d1c7ca445642192439cea314d` |
| Family label | `unknown` |
| File name | `bff7503710f200bb.zip` |
| File type | `zip` |
| First seen | `2026-08-20 23:12:16` |
| Reporter | `qvmt` |
| Tags | `Dev7Gang, microstealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c15fd36d4f68be5782d494325d1e8e47` |
| SHA-1 | `b7b5e7705590c854422a1fa42c44cb9c191e9c62` |
| SHA-256 | `d405153884a919e627f5682af122341b19007c5d1c7ca445642192439cea314d` |
| SHA3-384 | `8f37aed33e38d9c5d9ca09acb7e3c8a07ffad975896a82d3214a964091bd15a47c824cd954f7ef516dcf17feaa4d8988` |
| TLSH | `T1F6E7338060FF394AF8BDFB7A9D95B78E99A6189B04FF09772AC153014144DCBE6DC508` |
| SSDEEP | `1572864:FA/1+R4IcTiHqA0iWx97jA3TqnMuJFvAv+++++++3+++++++M70T:F8+IeKMWx9gqnM7+++++++3+++++++f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_d4051538
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d405153884a919e627f5682af122341b19007c5d1c7ca445642192439cea314d"
    family = "unknown"
    file_name = "bff7503710f200bb.zip"
    file_type = "zip"
    first_seen = "2026-08-20 23:12:16"
  condition:
    hash.sha256(0, filesize) == "d405153884a919e627f5682af122341b19007c5d1c7ca445642192439cea314d"
}
```

### Sample 44: `3f1ec38d7dda0015`

| Field | Value |
|---|---|
| SHA-256 | `3f1ec38d7dda00155eadc319f52cfec15128ef6a52adc4e97747238a04a68290` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-20 22:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c245cda0cc0ba3c184b6c2de629d0f0` |
| SHA-256 | `3f1ec38d7dda00155eadc319f52cfec15128ef6a52adc4e97747238a04a68290` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_3f1ec38d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f1ec38d7dda00155eadc319f52cfec15128ef6a52adc4e97747238a04a68290"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 22:52:10"
  condition:
    hash.sha256(0, filesize) == "3f1ec38d7dda00155eadc319f52cfec15128ef6a52adc4e97747238a04a68290"
}
```

### Sample 45: `e313c09240d94d6f`

| Field | Value |
|---|---|
| SHA-256 | `e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26` |
| Family label | `RemusStealer` |
| File name | `e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26.exe` |
| File type | `exe` |
| First seen | `2026-08-20 22:36:00` |
| Reporter | `Tuxxin` |
| Tags | `exe, RemusStealer, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c66a5720f35976345d324baf56fcd83` |
| SHA-1 | `9fa08cfd4286a11fcdfca4f9833952187e9d857f` |
| SHA-256 | `e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26` |
| SHA3-384 | `28e9df2dbd686b0513726988e2bb0434ce2cfb9834b3346a8956cfdae25feb759bbd2562d09dacf894cf90aab3be72df` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T12C54BF45F7A660ECE1B78974C9154662FB7B3A560340AF6F0361CB72BF136A0BD18B21` |
| SSDEEP | `6144:R0rVrlm1wui0DNiJC7PAQW04qeZMa0H7ip4MQSe:IVrlm1w70h57bW02Ma0bip4Ye` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_045_e313c092
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26"
    family = "RemusStealer"
    file_name = "e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26.exe"
    file_type = "exe"
    first_seen = "2026-08-20 22:36:00"
  condition:
    hash.sha256(0, filesize) == "e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26"
}
```

### Sample 46: `b22207f05d3a669d`

| Field | Value |
|---|---|
| SHA-256 | `b22207f05d3a669d95d750fced07c567733503c2dac83cb599b7b2ab588f8547` |
| Family label | `unknown` |
| File name | `NotaFiscal_Emissao_9512993795129937.zip` |
| File type | `zip` |
| First seen | `2026-08-20 22:19:09` |
| Reporter | `johnk3r` |
| Tags | `certificadogovbr-dynv6-net, nfe-emissao-org, notaemitida-dynv6-net, phantom, stealer, suporteseguro-sbs, vamosestourar-sbs, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e252e0abc70f06ce2ff0e0da4b196697` |
| SHA-1 | `d4ab49117ea8e8c2c9f7087d81184368f9e6a3c7` |
| SHA-256 | `b22207f05d3a669d95d750fced07c567733503c2dac83cb599b7b2ab588f8547` |
| SHA3-384 | `abb8ca29ba2ac1d3377b6412af98d6b5a6808e899101da0fabe071f65bd7945cebb4d06b6336806983afb2e0fa516258` |
| TLSH | `T15FE026EBEF820053CF9A9AF220B90834065C51A8B8235A036F71428A9C100556F0ADA4` |
| SSDEEP | `6:5j38llM/hXJIpX3cgLmeM8elCZxbj8WNyZ8y0c1LAqi1r7F8llYtxKRX/hXJNt+Q:5j380JJHGJM8eQZxAZDLni1r7F8wOpJP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_b22207f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b22207f05d3a669d95d750fced07c567733503c2dac83cb599b7b2ab588f8547"
    family = "unknown"
    file_name = "NotaFiscal_Emissao_9512993795129937.zip"
    file_type = "zip"
    first_seen = "2026-08-20 22:19:09"
  condition:
    hash.sha256(0, filesize) == "b22207f05d3a669d95d750fced07c567733503c2dac83cb599b7b2ab588f8547"
}
```

### Sample 47: `27b521e776ee083b`

| Field | Value |
|---|---|
| SHA-256 | `27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af` |
| Family label | `RemusStealer` |
| File name | `27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af.exe` |
| File type | `exe` |
| First seen | `2026-08-20 22:11:27` |
| Reporter | `Tuxxin` |
| Tags | `exe, RemusStealer, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79f820d76093b542c937cce8ebda5867` |
| SHA-1 | `fa2b2b2528a476d1110a5b7cf1f4aae3de93dc04` |
| SHA-256 | `27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af` |
| SHA3-384 | `f707ee77e0d6109c963a0148eaee469a42bf003db628208b4b834f22d497b8d0bac97db20007f011d513fb8398ce808d` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1A275230133E0107AD47E9770A5F24B572AB1B8E3DF30D69F12D966190E23AA6D63173B` |
| SSDEEP | `24576:qOKB+Us6j8KdgLqzqXiqT2UU72jvqSL2rseI2RKA09EC8IWMOxhynMTCADSI4:TaR86Zf2zUSWSws/2RKASwQETCO` |
| ICON-DHASH | `f1d1d0d0e4c8d8c8` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_047_27b521e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af"
    family = "RemusStealer"
    file_name = "27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af.exe"
    file_type = "exe"
    first_seen = "2026-08-20 22:11:27"
  condition:
    hash.sha256(0, filesize) == "27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af"
}
```

### Sample 48: `9595ef2ef7db78d3`

| Field | Value |
|---|---|
| SHA-256 | `9595ef2ef7db78d3e980077a39b57b167bec665e3f82646ba596bc4da9402ff3` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-20 21:52:12` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7995feb27b90732c63a5617f94b8ccf0` |
| SHA-256 | `9595ef2ef7db78d3e980077a39b57b167bec665e3f82646ba596bc4da9402ff3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_9595ef2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9595ef2ef7db78d3e980077a39b57b167bec665e3f82646ba596bc4da9402ff3"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 21:52:12"
  condition:
    hash.sha256(0, filesize) == "9595ef2ef7db78d3e980077a39b57b167bec665e3f82646ba596bc4da9402ff3"
}
```

### Sample 49: `fe90b0f1eb82ff69`

| Field | Value |
|---|---|
| SHA-256 | `fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309` |
| Family label | `CoinMiner` |
| File name | `fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309.exe` |
| File type | `exe` |
| First seen | `2026-08-20 21:46:03` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f47881dc207b40b3a3a2725b7d074b2` |
| SHA-1 | `2be8f65ded58b65e0e5b830bc76e90ccb4d94394` |
| SHA-256 | `fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309` |
| SHA3-384 | `ba145ea000408eec794170768e1502a145d4fcfb172753d2c8a5f2bd04185231ab1c621a08c5ae2afada5d0784e9b13b` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1893633A6AD8B80B0D147C7F5916374ACB33F7B990964BD1A76CC29884E96F00A53F3C1` |
| SSDEEP | `98304:2XZ5+7x3RYl7xoasvoy3uqYu/t7jTVn9hEMMADozcIVqPK/kGGPzBqqq/x:2rax3uLstuqFLV9hRbrIVqy/vGrcV` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_049_fe90b0f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309"
    family = "CoinMiner"
    file_name = "fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309.exe"
    file_type = "exe"
    first_seen = "2026-08-20 21:46:03"
  condition:
    hash.sha256(0, filesize) == "fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309"
}
```

### Sample 50: `f7223a2dd6a1e31d`

| Field | Value |
|---|---|
| SHA-256 | `f7223a2dd6a1e31d374df80194f141ef33428d757a33bcbecc6b04335d830399` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-20 21:34:18` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0450ad0d94496e174831df51723ccc29` |
| SHA-1 | `9ba15194373b3296374817a9adcfed2ca9ed60c5` |
| SHA-256 | `f7223a2dd6a1e31d374df80194f141ef33428d757a33bcbecc6b04335d830399` |
| SHA3-384 | `ec99a2d47113ea183f1d244b2be965f2df0e5ca117c7c04aa021a6089007e2e5734d0d97bcd0a44539562b388d3c60b5` |
| TLSH | `T1FF31609F14146B322002DA8D73663448B6CD95EB6D5FD7D4EC480EAA86883CCF266F5D` |
| SSDEEP | `24:+mRmg9bKOyDFXZkxsaRprUq6XdWIOixH4EhH:+mRmgxEF07OVxHjH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_f7223a2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7223a2dd6a1e31d374df80194f141ef33428d757a33bcbecc6b04335d830399"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-20 21:34:18"
  condition:
    hash.sha256(0, filesize) == "f7223a2dd6a1e31d374df80194f141ef33428d757a33bcbecc6b04335d830399"
}
```

### Sample 51: `e7c5f34dbbae4d49`

| Field | Value |
|---|---|
| SHA-256 | `e7c5f34dbbae4d49edee90f7ad98c6e548f50b8c86a9f6ce0b15e49491cafabd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-20 21:09:38` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `795ffcf26fed5ce55a0ea4bf1ec86eae` |
| SHA-1 | `5234d4747032f35221b8fa44e887ca4e9c186df7` |
| SHA-256 | `e7c5f34dbbae4d49edee90f7ad98c6e548f50b8c86a9f6ce0b15e49491cafabd` |
| SHA3-384 | `34ce2c09c2e4232ae2c40361802d3f055035935fdf76f430a1a2b0f450f44b77765d5f62b8bb4e12459aa937e9d9414b` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1D2466C03BDA545A9C0AA9734C9B79612BB76BC88873133D72E50B6383F76BD06E75700` |
| SSDEEP | `49152:/+xLCeAxhC38a97UaefQnCBArgrTmC/dJ:2pCuZUzYyHv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_e7c5f34d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7c5f34dbbae4d49edee90f7ad98c6e548f50b8c86a9f6ce0b15e49491cafabd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-20 21:09:38"
  condition:
    hash.sha256(0, filesize) == "e7c5f34dbbae4d49edee90f7ad98c6e548f50b8c86a9f6ce0b15e49491cafabd"
}
```

### Sample 52: `64daa9889c22bf32`

| Field | Value |
|---|---|
| SHA-256 | `64daa9889c22bf3225dfbb6c4781a2cdfcec5d7a892fa1d517fcfdfd9b2f7582` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-20 21:04:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c947339f63ae041894955e1bf7a478d` |
| SHA-1 | `c032647f897103e385c79d751e6188669f2f7e5a` |
| SHA-256 | `64daa9889c22bf3225dfbb6c4781a2cdfcec5d7a892fa1d517fcfdfd9b2f7582` |
| SHA3-384 | `d7bffc34a46024c9f6702d5519fa6c4697197020f04d3fdfdb878a3fc3733da26ae473cc5a5723d5d429d70c44c3fd50` |
| TLSH | `T1E0236C6516857C14AA99C4375C7F2F0CBDAD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:Qr9NyXsZztC89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:eHusZocr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_64daa988
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64daa9889c22bf3225dfbb6c4781a2cdfcec5d7a892fa1d517fcfdfd9b2f7582"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-20 21:04:35"
  condition:
    hash.sha256(0, filesize) == "64daa9889c22bf3225dfbb6c4781a2cdfcec5d7a892fa1d517fcfdfd9b2f7582"
}
```

### Sample 53: `0fbb8667298388dc`

| Field | Value |
|---|---|
| SHA-256 | `0fbb8667298388dc86480f23653f085e8ab64a2407f6e38a83f709503f859824` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-08-20 20:56:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95e26d9fc34b5f08d77ee74b4241e0c3` |
| SHA-1 | `436c35478a902b8cc1edefbe8d90045584b650a4` |
| SHA-256 | `0fbb8667298388dc86480f23653f085e8ab64a2407f6e38a83f709503f859824` |
| SHA3-384 | `6d265658911f868be3830aa98abe7032e974f436e0b51a0f3b8fddbeb2952b5029b0d390d40a812cc9f3fd4d000b4dc0` |
| TLSH | `T1EC93B44E2E319FBEF6ACC23447B74A20A35923D523E096C5D2ACD9151F7038D681FBA4` |
| TELFHASH | `t1cf212c58497023e49b355c9a2a6eff7be1a030df57223d338e41b9adabad9815d00d0c` |
| SSDEEP | `1536:jH83Lmz1bfztZ+Zo9TYMHCo8ZAekNHB7T+0ht:jH7zFfztv9TYMio8ZM+Yt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_0fbb8667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fbb8667298388dc86480f23653f085e8ab64a2407f6e38a83f709503f859824"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-20 20:56:26"
  condition:
    hash.sha256(0, filesize) == "0fbb8667298388dc86480f23653f085e8ab64a2407f6e38a83f709503f859824"
}
```

### Sample 54: `c72c17b0abc3b8c1`

| Field | Value |
|---|---|
| SHA-256 | `c72c17b0abc3b8c184eafed3e983985016a4b201844425e7009eb00faf96cfbd` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-20 20:54:05` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a74495d6c63482b07be4356b44ef2461` |
| SHA-1 | `cdf326f80f33bdacc2dd0f152660d6e76f2b2837` |
| SHA-256 | `c72c17b0abc3b8c184eafed3e983985016a4b201844425e7009eb00faf96cfbd` |
| SHA3-384 | `03e4e49e5c85063f531d6f880c38c691fe68c4747d59859142bcfa7b18ef12ca7e19923e4fbc32e6a2e3ad68858030cc` |
| IMPHASH | `6c3b6d183accb18d09096992bd7ac7da` |
| TLSH | `T117563B12BA6B94BCD157C87483468A639E2130DB0B36B9FF418485383F6ABF15B3D764` |
| SSDEEP | `49152:u2q8dpytEdOrbg/8Xp8Zo9ooD2ZaoyvnJTmwG9UxivsoqxFTYjTz5nqFf1MXiBqE:FCYw4Yo3jT1qFYiiM5vv9iSa4QK` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_054_c72c17b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c72c17b0abc3b8c184eafed3e983985016a4b201844425e7009eb00faf96cfbd"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-20 20:54:05"
  condition:
    hash.sha256(0, filesize) == "c72c17b0abc3b8c184eafed3e983985016a4b201844425e7009eb00faf96cfbd"
}
```

### Sample 55: `47e0d69e42199c1c`

| Field | Value |
|---|---|
| SHA-256 | `47e0d69e42199c1c25dda55d38a5b1469b107621af410eb49617d102750c9503` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-20 20:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cadd173908329ed85b1210a73bc70a7b` |
| SHA-256 | `47e0d69e42199c1c25dda55d38a5b1469b107621af410eb49617d102750c9503` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_47e0d69e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e0d69e42199c1c25dda55d38a5b1469b107621af410eb49617d102750c9503"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 20:52:11"
  condition:
    hash.sha256(0, filesize) == "47e0d69e42199c1c25dda55d38a5b1469b107621af410eb49617d102750c9503"
}
```

### Sample 56: `ac06297b765ab80a`

| Field | Value |
|---|---|
| SHA-256 | `ac06297b765ab80aeafe86dec174c114a65e6e3e282c149dddd6179d30fcca88` |
| Family label | `Mirai` |
| File name | `bot.i686` |
| File type | `elf` |
| First seen | `2026-08-20 20:51:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9f1e7e938331897c5ceeae91e407579` |
| SHA-1 | `dac8bfd65d09723d3963bba5ddb2af1d779342e0` |
| SHA-256 | `ac06297b765ab80aeafe86dec174c114a65e6e3e282c149dddd6179d30fcca88` |
| SHA3-384 | `e3ae026c24ac8128f16c97a7fdf51ada9ea5c4ff0df8537550ad41e98d845c5c12f39f7b2093c9a00b113143e8e2dc96` |
| TLSH | `T11B634BC1F9C7D1F6E816047C606FB3BB8B33E42A40719A99EF95DE22D9236016227359` |
| TELFHASH | `t1c83124e75ebe08f8f3e46840971e2a472536e63b013172f905b26d8132f29c6c1b9c35` |
| SSDEEP | `768:eJr3E1ndkvu8KF8uXqtDQs3n6RolVWBTKhARu956IXBO92qCWqgl9/h8wPJSf+Ld:ei1n3tF2t7VWAAPIXBNzg3VpF9VjUB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_ac06297b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac06297b765ab80aeafe86dec174c114a65e6e3e282c149dddd6179d30fcca88"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-20 20:51:27"
  condition:
    hash.sha256(0, filesize) == "ac06297b765ab80aeafe86dec174c114a65e6e3e282c149dddd6179d30fcca88"
}
```

### Sample 57: `c29aba55285d4e1a`

| Field | Value |
|---|---|
| SHA-256 | `c29aba55285d4e1a8601261e6c543083b15018b9e5376cc01f267edc71eaea86` |
| Family label | `Vidar` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-08-20 20:50:41` |
| Reporter | `Kejult` |
| Tags | `dropper, exe, nsis, trojan, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a160911fcdff29109f0077dd3630090` |
| SHA-1 | `f6f27f0afabb3299fad1091c41bffd34bcf6960f` |
| SHA-256 | `c29aba55285d4e1a8601261e6c543083b15018b9e5376cc01f267edc71eaea86` |
| SHA3-384 | `1716b3928e496dc81d1ec2cf95cd1d13cc53c2e05beed3ba5aa00f5db4dd1817abeb77b4e86161db987ec4483c364adb` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T19418339153964555D0CFBFBC217F0FE2AF2B4AA0662D64E706638431F4A646BC98C2CF` |
| SSDEEP | `1572864:ELdkU4GiOB3GhtgejVFIABZI48z2Fi/S8JKBUmy+N5Xe6EfB7W7:E2E3+3paABZVPArg/bXeB7W7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_057_c29aba55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29aba55285d4e1a8601261e6c543083b15018b9e5376cc01f267edc71eaea86"
    family = "Vidar"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:50:41"
  condition:
    hash.sha256(0, filesize) == "c29aba55285d4e1a8601261e6c543083b15018b9e5376cc01f267edc71eaea86"
}
```

### Sample 58: `3304c3a91fdcec91`

| Field | Value |
|---|---|
| SHA-256 | `3304c3a91fdcec91e1fcf846f104d225bf6c3d7097b7b4c2f950f135b9c595ff` |
| Family label | `unknown` |
| File name | `3gaj9IOhsrmr.exe` |
| File type | `exe` |
| First seen | `2026-08-20 20:47:29` |
| Reporter | `Kejult` |
| Tags | `exe, packed, trojan, vmprotect` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c85af19375b971f70a1261f317b3e5b` |
| SHA-1 | `5d6f88253bc65fbe8a811f6a2f8fd08565dd0dea` |
| SHA-256 | `3304c3a91fdcec91e1fcf846f104d225bf6c3d7097b7b4c2f950f135b9c595ff` |
| SHA3-384 | `6a45a9a942f9ce990b85983aefe7710b1c6a7511e0239cea6e2bfc8e69d6f2631e4aedff23ad7ad7b5e6d57badb1c44f` |
| IMPHASH | `7f972135e4ef2afd8f6b7ede6e0f3f09` |
| TLSH | `T109B46BA3A39627FCC1E6C3748016362CF6A13F5546298696525AF7210F37A8C6F3EF44` |
| SSDEEP | `6144:O7EH/QnLidGsWh/QgpyfN3XS4ed6EMWggYu5l14kdo0FYWsLx3feOCIthOhPn3Oi:aEaLOlbV3v+66++Fo0WW4x3feqG/3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_3304c3a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3304c3a91fdcec91e1fcf846f104d225bf6c3d7097b7b4c2f950f135b9c595ff"
    family = "unknown"
    file_name = "3gaj9IOhsrmr.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:47:29"
  condition:
    hash.sha256(0, filesize) == "3304c3a91fdcec91e1fcf846f104d225bf6c3d7097b7b4c2f950f135b9c595ff"
}
```

### Sample 59: `b37f43cdd18ad9b8`

| Field | Value |
|---|---|
| SHA-256 | `b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509` |
| Family label | `Mirai` |
| File name | `b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509.elf` |
| File type | `elf` |
| First seen | `2026-08-20 20:46:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `149ac52e7afd8c7e2125e79d66f193bd` |
| SHA-1 | `ebba7622b2187efd45942f242b7e46ebad23d922` |
| SHA-256 | `b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509` |
| SHA3-384 | `7b57fe7fcca61f67e5856497ba02e21a43d393a023f57fdd53285b33f54fe7d380cbd5f9bd14177bf9956f2c9e0f948d` |
| TLSH | `T14D54D71A2E628F3EF269CB3447F74925975922D713E5D640F1ACD1102F2029EA46FFE8` |
| TELFHASH | `t1e8418d58097817f0a7266c5d099dff37d6a321db7e162c378e10e8aaab79b435d00c0c` |
| SSDEEP | `6144:r+zujuO1SM2YCmbGsj6mF4dNUZEssMOgh5oql:kYCajg8EssMOgh5oql` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_b37f43cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509"
    family = "Mirai"
    file_name = "b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:46:56"
  condition:
    hash.sha256(0, filesize) == "b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509"
}
```

### Sample 60: `7e6a2e24a32c7ec7`

| Field | Value |
|---|---|
| SHA-256 | `7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52` |
| Family label | `Mirai` |
| File name | `7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52.elf` |
| File type | `elf` |
| First seen | `2026-08-20 20:46:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b86d0c5b2b4c53faa4cb144ae8ba8190` |
| SHA-1 | `cd7e248adcd9b21cb33d305a521689d2577ce862` |
| SHA-256 | `7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52` |
| SHA3-384 | `f97b6c181e2a0a779010ce18f07d1b0f05ab717995a0e1157165f2ce93ce51f95832c41237e5071a9e1465ccd073e681` |
| TLSH | `T1D8345BD3BC11E9BEF84BE73B89574409B130A66301524A33B21F747BAF2A0955673EC6` |
| SSDEEP | `6144:4cPwIOlwcjoMDYHMVKFc0C+LrhyGM1ZEssMOgh5oqt:4cPwIJaKB6EssMOgh5oqt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_7e6a2e24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52"
    family = "Mirai"
    file_name = "7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:46:52"
  condition:
    hash.sha256(0, filesize) == "7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52"
}
```

### Sample 61: `c3732db414d3db13`

| Field | Value |
|---|---|
| SHA-256 | `c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf` |
| Family label | `Mirai` |
| File name | `c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf.elf` |
| File type | `elf` |
| First seen | `2026-08-20 20:46:48` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25b82e931c43cc4207bddeff9a932f8a` |
| SHA-1 | `bcaa43796b7fd12d8e453d57d15f7b6ec843bb01` |
| SHA-256 | `c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf` |
| SHA3-384 | `bb4cfe823f98e6264e9a013ff852b5689697bc522c4f840c12bb6058585aef01760e7194948dbe4abca8d89bb5152fa1` |
| TLSH | `T179F38DC16AE3E0F1E543497A82AB97158A32E437021ED651FB6E2938BF02510D77B7DC` |
| TELFHASH | `t1156159fabd7a0ce8a7909c46d20e6b31bd4dab7b206072b605f3596133b354191b7c39` |
| SSDEEP | `3072:5Mpnc4UjyDozjvRPyOXOwTrrgJwVy56sXBOcq6u1EssMZc/T03ImIys61X1h5osd:5H4iyDozFPVr348cqnEssMOgh5oc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_c3732db4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf"
    family = "Mirai"
    file_name = "c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:46:48"
  condition:
    hash.sha256(0, filesize) == "c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf"
}
```

### Sample 62: `c3ddfee06487de1d`

| Field | Value |
|---|---|
| SHA-256 | `c3ddfee06487de1d376846a072aab90dde7be84c9edf47219eafa3b42fdbd895` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-20 20:46:43` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76834515d103d8df7893aed8a8f603b9` |
| SHA-1 | `6982f26b587e380ed5e4d341f9eb8831f69846bd` |
| SHA-256 | `c3ddfee06487de1d376846a072aab90dde7be84c9edf47219eafa3b42fdbd895` |
| SHA3-384 | `6d576084a589e4b494a33db348c9b7e16d4621dd75ea2782d582fc2c733b3101a64cd377088ed99bbee861061c2480fd` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T161F59C077C9084F6C096973698B76A22BB75F84C8B3533D72EA0A6742F763E11D76B04` |
| SSDEEP | `49152:5m6CLiRp9rEJpBy2fC71DjJHLbIcj4oK7dMt9/MqHQHx3d+bhGmo9Qs1Yw7JQc/a:5lf/gSDoHOlaz7JhkN1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_c3ddfee0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3ddfee06487de1d376846a072aab90dde7be84c9edf47219eafa3b42fdbd895"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:46:43"
  condition:
    hash.sha256(0, filesize) == "c3ddfee06487de1d376846a072aab90dde7be84c9edf47219eafa3b42fdbd895"
}
```

### Sample 63: `5c94555bf53b8243`

| Field | Value |
|---|---|
| SHA-256 | `5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333` |
| Family label | `Mirai` |
| File name | `5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333.elf` |
| File type | `elf` |
| First seen | `2026-08-20 20:45:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21d175d99c4f15542bdb30649a81334c` |
| SHA-1 | `9c03cbb3592c8000805f2ffcd4298e26b1faf541` |
| SHA-256 | `5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333` |
| SHA3-384 | `04be506b74196f905a5de50db593e3f8f8ab5b5a3ba441914ffcefaa67446ecb1e02aa1f7d98f251b9de6b498691a8db` |
| TLSH | `T1EAC32A957CE39666C6D3463BFB4F810933166297C3CEB112FD1D4B643F8A12A8A77980` |
| TELFHASH | `t103e05540fd388b1a8cd22a74ec8c07b5d8235313212297299f58dae4d83e119a34ce0e` |
| SSDEEP | `3072:9RoCXr5jVN8oAziaGKgquwa5ygu1EssMZc/T03ImIys61X1h5oD:3oCXr5jVNgzequJ5yBEssMOgh5o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_5c94555b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333"
    family = "Mirai"
    file_name = "5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:45:59"
  condition:
    hash.sha256(0, filesize) == "5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333"
}
```

### Sample 64: `f5d6944d1133d2b4`

| Field | Value |
|---|---|
| SHA-256 | `f5d6944d1133d2b45f1b002172212d72bf3e6e6cb612a42f9f7773bb1bbeec83` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-08-20 20:45:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85a1b842580a3c1050bc4bbbec174d4a` |
| SHA-1 | `a3e20800020ad18f6839deb631020cd5b5ea1e7e` |
| SHA-256 | `f5d6944d1133d2b45f1b002172212d72bf3e6e6cb612a42f9f7773bb1bbeec83` |
| SHA3-384 | `534642231a05e33f0046edda35978dcfbc8e8558d8ba497efc6db62d3aff8b762d136c56d93cea314d69b26a64444f83` |
| TLSH | `T1E1633A0766D190FDC5E9D1B81AAF6235D863F4781372B61A23C0FA1A7E9DF202F5E205` |
| TELFHASH | `t1c83145a17a461cd4a2f7f6327306e5640c7c0e6500d036e2db32a8f6db627d509b4c3b` |
| SSDEEP | `1536:7V5G65Zc0awTBlmvBkZsYxmDQxiTbTlg4y0/UkwAAAAAAAAAAAAAAAA:7V5G65ZNBlm5kZRoQxgTlg47ckwAAAAf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_f5d6944d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5d6944d1133d2b45f1b002172212d72bf3e6e6cb612a42f9f7773bb1bbeec83"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 20:45:25"
  condition:
    hash.sha256(0, filesize) == "f5d6944d1133d2b45f1b002172212d72bf3e6e6cb612a42f9f7773bb1bbeec83"
}
```

### Sample 65: `39f366b6e4850cc9`

| Field | Value |
|---|---|
| SHA-256 | `39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371` |
| Family label | `AokigaharaStealer` |
| File name | `Loader.exe` |
| File type | `exe` |
| First seen | `2026-08-20 20:44:49` |
| Reporter | `Kejult` |
| Tags | `AokigaharaStealer, exe, loader, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e790e17222b7861785fdd90e72bcb7dc` |
| SHA-1 | `cc4059643fd978e38a9b06a95a8bd98f16ef5011` |
| SHA-256 | `39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371` |
| SHA3-384 | `9c4ee449ab473d03fa78a197f7e169e319ea55094fd3fdd1fcd456666b7e197835b127fc7ad514dadfc599cc9e917d43` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T168D55A077E9044E5D0AAE33689A646557B74BC0C8B3133E72EA0BE782F727D19E35B44` |
| SSDEEP | `49152:HtkxF4vLBs63+reo7zDbkz9BNKxmZ/+y2:Hek3TfwY/+y2` |

#### Technical Assessment

- The sample is tracked as `AokigaharaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AokigaharaStealer_065_39f366b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371"
    family = "AokigaharaStealer"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:44:49"
  condition:
    hash.sha256(0, filesize) == "39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371"
}
```

### Sample 66: `1ce78aa4c9ff577f`

| Field | Value |
|---|---|
| SHA-256 | `1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0` |
| Family label | `Mirai` |
| File name | `1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0.elf` |
| File type | `elf` |
| First seen | `2026-08-20 20:43:26` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bbccb54f0764e994fbc1f508d66cad0` |
| SHA-1 | `03563e3821cf6865a1a1cdd5659a36e8366f3f03` |
| SHA-256 | `1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0` |
| SHA3-384 | `543afaa4fef25298f075eda32238d901d7709d2a7929c7ca742cc4e6abca02773a3e9e80c83449b0f3315f17450aa1e5` |
| TLSH | `T1C5147CA3CCB27E60D316D439F2628A3D5B13A42342471E68B46EC2745F83D99F2A57F4` |
| SSDEEP | `3072:87RHvVK4cJ8nM1GUjlb5PoHTdp4jGWwb0t89TAIu1EssMZc/T03ImIys61X1h5oV:81hqP5PoHRsTw6cTApEssMOgh5oV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_1ce78aa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0"
    family = "Mirai"
    file_name = "1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:43:26"
  condition:
    hash.sha256(0, filesize) == "1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0"
}
```

### Sample 67: `b1a9ae7d0b9b6bc2`

| Field | Value |
|---|---|
| SHA-256 | `b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609` |
| Family label | `Mirai` |
| File name | `b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609.elf` |
| File type | `elf` |
| First seen | `2026-08-20 20:41:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13c14e6c86e4d98d296cb68668d3d9d2` |
| SHA-1 | `16e881bf7121174ac1ab6629753bf05618728cc3` |
| SHA-256 | `b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609` |
| SHA3-384 | `827a5c0f0b57405aae9964d10fd8f70383cc6d8f1212bac13f5e61d45f5bc66f43a0b178a833fef23320f70d0ec15031` |
| TLSH | `T11B443B56AA824A13C5C3173AFA9F41063322E65693DBB306FD1CABB43F8725E4E73541` |
| TELFHASH | `t14c4131311f26a5235ea1c90888eda3aa101da313a640ff73df29c58c911a0dfe637d0f` |
| SSDEEP | `6144:13htnpS1sNu3DRPeH00ABkPcaGzolGHcJ2AGCFwEssMOgh5o7KTlL/KoU8+bfLk9:j9pS1sSDRPeH03BkPcaGzolGitcEssMj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_b1a9ae7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609"
    family = "Mirai"
    file_name = "b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:41:04"
  condition:
    hash.sha256(0, filesize) == "b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609"
}
```

### Sample 68: `c479eaa06b1794ff`

| Field | Value |
|---|---|
| SHA-256 | `c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d` |
| Family label | `Mirai` |
| File name | `c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d.elf` |
| File type | `elf` |
| First seen | `2026-08-20 20:41:00` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11af571333b7d3dbc11e00fb12e51b4c` |
| SHA-1 | `001975014dacee389455cc2d2ee2bcbc3c907e4e` |
| SHA-256 | `c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d` |
| SHA3-384 | `92fe5b997997f43472ccfed75a4f2f2c94ba41fd74ad1e9afbdd8b9dfc0c44a85b4485dd0a697c13cd3af22bcfe11ce8` |
| TLSH | `T1BF54D80AAFB21FFBD86FDD3706E91606248C641722983B35753CD518BF4A64B4AE3C64` |
| SSDEEP | `3072:iM4qCH1HXnm00RRYAMYcYJX2smtMap1r7UmOcmjV+cpvss4u1EssMZc/T03ImIy+:N4ujYA7cYEsWPqHx/0sZEssMOgh5oI+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_c479eaa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d"
    family = "Mirai"
    file_name = "c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:41:00"
  condition:
    hash.sha256(0, filesize) == "c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d"
}
```

### Sample 69: `9bb80cc73f15beb3`

| Field | Value |
|---|---|
| SHA-256 | `9bb80cc73f15beb3ee8272398adfda9f3395cd9a52f82566259a86fb931f39ba` |
| Family label | `Mirai` |
| File name | `bot.arm7` |
| File type | `elf` |
| First seen | `2026-08-20 20:37:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e5d43adc31f667631a7ea7617cfcf6b` |
| SHA-1 | `fc26d99a6c78d457177f4eb4cc5aa2cea50eb8a0` |
| SHA-256 | `9bb80cc73f15beb3ee8272398adfda9f3395cd9a52f82566259a86fb931f39ba` |
| SHA3-384 | `ebf0632860def1588867270f3ac489de862246f1bcae50d4de8a2e4bec24c47b3c207366a06b51a1b9460da056a79901` |
| TLSH | `T1E9F31946A7409B13C1D22B76EBDF42053323DB58D3A763055928BFF43F87A9E4E2650A` |
| TELFHASH | `t181214e26667a882abe318860ddbc9bf25416531723442b32df3fc5dc182b446e52ac0f` |
| SSDEEP | `3072:TIZAX8e7AkKablvzVhVDJFWvGDX35g4OO2brd/M/9z+RuqAbKW:ToePKablvzVhVJFPXJghO2brlM/9KvA5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_9bb80cc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bb80cc73f15beb3ee8272398adfda9f3395cd9a52f82566259a86fb931f39ba"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-20 20:37:49"
  condition:
    hash.sha256(0, filesize) == "9bb80cc73f15beb3ee8272398adfda9f3395cd9a52f82566259a86fb931f39ba"
}
```

### Sample 70: `cbbe8baef6375199`

| Field | Value |
|---|---|
| SHA-256 | `cbbe8baef63751998bb92e30ea1f68b8884c252a3b5447c6ed4b537262f78e3b` |
| Family label | `Mirai` |
| File name | `bot.spc` |
| File type | `elf` |
| First seen | `2026-08-20 20:31:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7983009b612592acc3bc58b4cab6723` |
| SHA-1 | `041d5f2043c43ee26c160d0026bd5a96007b1bd6` |
| SHA-256 | `cbbe8baef63751998bb92e30ea1f68b8884c252a3b5447c6ed4b537262f78e3b` |
| SHA3-384 | `88c9739b53d82b73c23d0aff7a2cb4e69ddc12f8eeca9f5efbb9e013c78b5d6a59bc1aecc9db13a4cdffb0dfbbc6b71e` |
| TLSH | `T18A835B25BE65093BC5C8617A61E78321F2F6438E64BC861A7DB10E8CBF647403617BF6` |
| SSDEEP | `768:Vm7yCSCJBdNXL5cmCP0wy9Li4mjHPvT0StWkwNbwO+oM5VrIs4oLFlkhAf/FVWqT:VYPpnjXVLW0XiyStFwsoM5IhAXF1tUdQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_cbbe8bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbbe8baef63751998bb92e30ea1f68b8884c252a3b5447c6ed4b537262f78e3b"
    family = "Mirai"
    file_name = "bot.spc"
    file_type = "elf"
    first_seen = "2026-08-20 20:31:56"
  condition:
    hash.sha256(0, filesize) == "cbbe8baef63751998bb92e30ea1f68b8884c252a3b5447c6ed4b537262f78e3b"
}
```

### Sample 71: `79f19dfccf9943e5`

| Field | Value |
|---|---|
| SHA-256 | `79f19dfccf9943e58b1c616ef28dd56b816a4aaf8de1370536f649bae236d55e` |
| Family label | `Mirai` |
| File name | `bot.arm5` |
| File type | `elf` |
| First seen | `2026-08-20 20:30:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `387e6a94e53ddd4c8f497dbcee4fdbd9` |
| SHA-1 | `4a4ac43c57c217adc040a8826f246f3e7dfeb0bd` |
| SHA-256 | `79f19dfccf9943e58b1c616ef28dd56b816a4aaf8de1370536f649bae236d55e` |
| SHA3-384 | `f2ff7305bfb1de77ebec0f76d7d970a46bf13576f35e9c4d7a0b306c070d643ac3d3d6ac8379088af52967dae4083bfa` |
| TLSH | `T1D1631BC5B940BB21C7C256B7FF0F425D77194398E2EA3343992D2FA0778B85A0E5760A` |
| TELFHASH | `t1bc21d050aecc0edcd7d0c634c29a763b7a6622983b420c694b057a8f9637dd67129c36` |
| SSDEEP | `1536:VfDxf9eZWimSiRpZKx2OuJ9eGMG1++S0ri:Vd1w/iRp0cevG4Ai` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_79f19dfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f19dfccf9943e58b1c616ef28dd56b816a4aaf8de1370536f649bae236d55e"
    family = "Mirai"
    file_name = "bot.arm5"
    file_type = "elf"
    first_seen = "2026-08-20 20:30:26"
  condition:
    hash.sha256(0, filesize) == "79f19dfccf9943e58b1c616ef28dd56b816a4aaf8de1370536f649bae236d55e"
}
```

### Sample 72: `86c27d01d30f0bb9`

| Field | Value |
|---|---|
| SHA-256 | `86c27d01d30f0bb941e50f4a9c39d4a46cc7a6d325fa44cfd72a908815b1d4b0` |
| Family label | `Mirai` |
| File name | `bot.mpsl` |
| File type | `elf` |
| First seen | `2026-08-20 20:28:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38f0d0e2d428a761fb944cf662c604da` |
| SHA-1 | `872f679d9c274808620a728fd5325cb321384d1d` |
| SHA-256 | `86c27d01d30f0bb941e50f4a9c39d4a46cc7a6d325fa44cfd72a908815b1d4b0` |
| SHA3-384 | `411358818c42aaac3022f75806a7df60c34bcf94edffa2987ce1461242fe77e52670fd7ee17d72be9cae1032736417f9` |
| TLSH | `T1BB93B54AAB614EFBDCAFDE3346A90B0635DC544722A83B753674C828F54A64F0AD3C64` |
| SSDEEP | `1536:fYOb7eBBj59/wXD4rzOpwcFja/S5wRMBbTWZZtK5ucw5t2e+5R0SyQQH:hiBkD5e/TRaWZiGwzn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_86c27d01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c27d01d30f0bb941e50f4a9c39d4a46cc7a6d325fa44cfd72a908815b1d4b0"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-08-20 20:28:52"
  condition:
    hash.sha256(0, filesize) == "86c27d01d30f0bb941e50f4a9c39d4a46cc7a6d325fa44cfd72a908815b1d4b0"
}
```

### Sample 73: `758e750c4c2fb647`

| Field | Value |
|---|---|
| SHA-256 | `758e750c4c2fb6478b28d0c7d2a6d55eedbb0b5ac65e4795e08eeee472298e3e` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-20 20:28:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d58f2c42942d825d1eb8779d45e32b06` |
| SHA-1 | `f9211e5358f0b719ded5451188cd21587902ceeb` |
| SHA-256 | `758e750c4c2fb6478b28d0c7d2a6d55eedbb0b5ac65e4795e08eeee472298e3e` |
| SHA3-384 | `443300035052895eb25f17b201938eebd2dcb25b1444acf08e055199b4a8d678a139c369dc01b23ebaf03f86f0b4ed32` |
| TLSH | `T11D341756B8D29B11C6C2517EFF0E514E33132B7AD2CE7112FD2CAA743F8A46B0A7A541` |
| TELFHASH | `t11ee07d019b4544d4f4d75b44896a32058ae5e2ab4e051063c6d07b1cdd034c0b43d417` |
| SSDEEP | `6144:6NIJekxWI02A3955qgaXDaZcb9rBKXDEvacCywEssMOgh5oN:H8kxWI02A39jDaXDayvKzEvEEssMOghO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_758e750c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "758e750c4c2fb6478b28d0c7d2a6d55eedbb0b5ac65e4795e08eeee472298e3e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-20 20:28:51"
  condition:
    hash.sha256(0, filesize) == "758e750c4c2fb6478b28d0c7d2a6d55eedbb0b5ac65e4795e08eeee472298e3e"
}
```

### Sample 74: `cfb3f5de317afedb`

| Field | Value |
|---|---|
| SHA-256 | `cfb3f5de317afedb369286a65dfee58c47e6b9b58a3ab00bb8ee88395eb72b25` |
| Family label | `Mirai` |
| File name | `bot.sh4` |
| File type | `elf` |
| First seen | `2026-08-20 20:27:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36800aeee779727530891672825750d6` |
| SHA-1 | `a1812a2916b036350e832444454ef0b752904f4e` |
| SHA-256 | `cfb3f5de317afedb369286a65dfee58c47e6b9b58a3ab00bb8ee88395eb72b25` |
| SHA3-384 | `ab32aed858a680c73fd0803f2b1ae1e6fbb739456568d95df3c87209eda85037d305673092be8ed2e8d24f05ad4ffbe4` |
| TLSH | `T1BC638D92CAB56D38D62889F07125CF398723D51081971FFA9125C769E083DEDF29A3F8` |
| SSDEEP | `768:6H4XH/fvfxtXM6+Skmcca+0XqK7q98Aa5oS7V+zeCxnG1W0/d/f0iK8Zv9vtIM:xHXvfvXnIhOK7q9++S2eCxHhz8Z5t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_cfb3f5de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfb3f5de317afedb369286a65dfee58c47e6b9b58a3ab00bb8ee88395eb72b25"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-08-20 20:27:30"
  condition:
    hash.sha256(0, filesize) == "cfb3f5de317afedb369286a65dfee58c47e6b9b58a3ab00bb8ee88395eb72b25"
}
```

### Sample 75: `e2edd564b250d9e8`

| Field | Value |
|---|---|
| SHA-256 | `e2edd564b250d9e82c02a7ead600c2022d10f04b4898fe595ecb811a8fb82576` |
| Family label | `unknown` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-20 20:27:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e36ddf71c8b1f616d38ee0a6ce30536b` |
| SHA-1 | `3b8a9ea5f294dea9ed5b30be74dd9b2a3a33f2de` |
| SHA-256 | `e2edd564b250d9e82c02a7ead600c2022d10f04b4898fe595ecb811a8fb82576` |
| SHA3-384 | `59aedf24b1c5f74a904c669067cc60d2e0d27801c29a0c27690e729d28f0067c4f3803b512f56b57b5cc87a55ca995d2` |
| TLSH | `T18E441859F880DB6186D539BAFA4D42AC730307B9D3EA7106CD154B3037EB96B4B3AB41` |
| SSDEEP | `6144:Q4o+Y73SvZXrlySPONuF9FbBId9VNAOMjOTl8XSOJq9fy4:PJYLSxb5O+WfTMi8XrQL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_e2edd564
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2edd564b250d9e82c02a7ead600c2022d10f04b4898fe595ecb811a8fb82576"
    family = "unknown"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-20 20:27:28"
  condition:
    hash.sha256(0, filesize) == "e2edd564b250d9e82c02a7ead600c2022d10f04b4898fe595ecb811a8fb82576"
}
```

### Sample 76: `1e29360b5e4f5806`

| Field | Value |
|---|---|
| SHA-256 | `1e29360b5e4f58062895cac59fa21b55c24f45c2d2d02a52a149787bee0634c1` |
| Family label | `Mirai` |
| File name | `bot.x86` |
| File type | `elf` |
| First seen | `2026-08-20 20:25:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24eec0e7b8c76b9cffecfc066c953740` |
| SHA-1 | `28f4a6ab862720e895523f0542149d8f1961362a` |
| SHA-256 | `1e29360b5e4f58062895cac59fa21b55c24f45c2d2d02a52a149787bee0634c1` |
| SHA3-384 | `8809453ba4066dd97f6099d886341cea2df36379bfc723086a9d1be0d228d229c7eb855bcdb53455fdbe4bf8521de4dc` |
| TLSH | `T1B6534B85BAC2E8F6F852007D60BF5B724E33E839A076DE9AC7E994379C06540D21775C` |
| TELFHASH | `t13e31e3b32da70decf3d07888c72e22921b39da7b462075f981b2984527f2ac551b5939` |
| SSDEEP | `1536:d++zlLn7kri2GZLBtC0Z4XsZ11LxKJuPSFzSjDrI:dp1Wi2+BsIisZ3LxK4qFd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_1e29360b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e29360b5e4f58062895cac59fa21b55c24f45c2d2d02a52a149787bee0634c1"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-20 20:25:40"
  condition:
    hash.sha256(0, filesize) == "1e29360b5e4f58062895cac59fa21b55c24f45c2d2d02a52a149787bee0634c1"
}
```

### Sample 77: `8ce9edf74cedf977`

| Field | Value |
|---|---|
| SHA-256 | `8ce9edf74cedf977fa6e22c2811fd5b8299ecd27fc0d80c7e15272d9b2fbba69` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-20 20:25:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2855dcd0b2ceafcd7232625fca058f6` |
| SHA-1 | `bcda313f90f7d3e514cb1afff487d64328ad0170` |
| SHA-256 | `8ce9edf74cedf977fa6e22c2811fd5b8299ecd27fc0d80c7e15272d9b2fbba69` |
| SHA3-384 | `8e0e3606967d5f929082d1d3d8137801370c27e421dcd2b6374548d90a48b39e09d85f7e5ab525af3698da0c024aff5e` |
| TLSH | `T1E4244A02B7690503D2632DB0373B57E1939FE45321E4F644790FAB889F72932A696DCE` |
| SSDEEP | `6144:9WfWyLoIYAG19ocVbpx2qyS05jdHhhEssMOgh5otD:Y8ldVbKv5prEssMOgh5otD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_8ce9edf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ce9edf74cedf977fa6e22c2811fd5b8299ecd27fc0d80c7e15272d9b2fbba69"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-20 20:25:38"
  condition:
    hash.sha256(0, filesize) == "8ce9edf74cedf977fa6e22c2811fd5b8299ecd27fc0d80c7e15272d9b2fbba69"
}
```

### Sample 78: `d634856eecdf9465`

| Field | Value |
|---|---|
| SHA-256 | `d634856eecdf9465000e435cb8e8f8b57896d69086ed67ddd9a1a990cefc3b50` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-20 20:06:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6028ff769d0ff0aa079c1e4e14b04856` |
| SHA-1 | `f7cec104156ed9f37b6ee0c96d4b30ecaaacf512` |
| SHA-256 | `d634856eecdf9465000e435cb8e8f8b57896d69086ed67ddd9a1a990cefc3b50` |
| SHA3-384 | `479ad9ec41825cf0379fefdd99ea24b33db45365bedcb9bce6e129b96b98575664e4454eb455d77e9575fa765d0340e2` |
| TLSH | `T1E0C27D966A867C44BEC98B3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11F9CD618B1A` |
| SSDEEP | `768:48vCB+25j6es8RSV9FYpMSUpi+20qUpi+20YQX:48l25JSzd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_d634856e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d634856eecdf9465000e435cb8e8f8b57896d69086ed67ddd9a1a990cefc3b50"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-20 20:06:50"
  condition:
    hash.sha256(0, filesize) == "d634856eecdf9465000e435cb8e8f8b57896d69086ed67ddd9a1a990cefc3b50"
}
```

### Sample 79: `d3c414ea55ff51e3`

| Field | Value |
|---|---|
| SHA-256 | `d3c414ea55ff51e39378044996c77cf65c1c2403b8ad232bb8b5c8ee7cadd393` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-20 20:01:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45d63f8cb549887a9738ff84fb5ecdf5` |
| SHA-1 | `87410bb0ac375931f8047e04aa28a08f343de9ec` |
| SHA-256 | `d3c414ea55ff51e39378044996c77cf65c1c2403b8ad232bb8b5c8ee7cadd393` |
| SHA3-384 | `4a8190832cb4bbc778f4af1242ba6b033f230a2e39cdeab29df891ac8acec66882edd2e98168dab82ad23ce35e755b26` |
| TLSH | `T1EF246D1278E190FDC987C1798F9FA026D431B81B1125B22A778DBE653F4EE315B7E284` |
| TELFHASH | `t13e71cd302eaa7a98b2e3c74a730ed66dfc7209112ee275d99e537dd8dc432884d72442` |
| SSDEEP | `3072:0ZCFOpAaiNge0MEU9wQ/quhO9K8x1xdFI37tyHC5xyuWH3QJu1EssMZc/T03ImIj:0ZCMX6HBhZ37qimQyEssMOgh5opn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_d3c414ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3c414ea55ff51e39378044996c77cf65c1c2403b8ad232bb8b5c8ee7cadd393"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 20:01:34"
  condition:
    hash.sha256(0, filesize) == "d3c414ea55ff51e39378044996c77cf65c1c2403b8ad232bb8b5c8ee7cadd393"
}
```

### Sample 80: `de24c79b1a0383bc`

| Field | Value |
|---|---|
| SHA-256 | `de24c79b1a0383bc6afcb7224f273d84207d948c86e84ce4709cdfc5b82a71fb` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-20 20:01:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9d55d6b3a8495bbb27c7132b56b0ea4` |
| SHA-1 | `c6cd6f5485e3486d5c59ce8f3cde61639fb0b91b` |
| SHA-256 | `de24c79b1a0383bc6afcb7224f273d84207d948c86e84ce4709cdfc5b82a71fb` |
| SHA3-384 | `c8bcec95c73eb05ccfa1bf2e8c71d4d9780a65faa512f20bea71d3e03017b0747bb2b01495476f6f3797aa412bfb3f21` |
| TLSH | `T105244945BCE29A22C6D2567BFB4E414D331A13AAD2DE7102FD2D5F603FCA45A4E7B081` |
| TELFHASH | `t168e0263a48c115fcbabc069544e7a338649af1be068854b28344bc781d238d72536902` |
| SSDEEP | `6144:M1DR3qOzT6ih4AJfSX4RQKzgFLfYE5EssMOgh5oP:M1JqOzT6Y4A4X42IW7EssMOgh5oP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_de24c79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de24c79b1a0383bc6afcb7224f273d84207d948c86e84ce4709cdfc5b82a71fb"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-20 20:01:33"
  condition:
    hash.sha256(0, filesize) == "de24c79b1a0383bc6afcb7224f273d84207d948c86e84ce4709cdfc5b82a71fb"
}
```

### Sample 81: `99ed5274e7d4abd0`

| Field | Value |
|---|---|
| SHA-256 | `99ed5274e7d4abd06e4ce3ee1b893b0d2ed2082f62712fe6fe8e350013f63a5c` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-20 19:59:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `023b7572b5076283e3f572ad7d38d58c` |
| SHA-1 | `e07ceee0370085ab1944f1954a2bb7163e3b0bdb` |
| SHA-256 | `99ed5274e7d4abd06e4ce3ee1b893b0d2ed2082f62712fe6fe8e350013f63a5c` |
| SHA3-384 | `ac0a56f799b34e6aa4cd09670ea3ad3be60d3de322a4f3f7c1739a8351a1c32ef7c637629f205822c4d08971715e9f82` |
| TLSH | `T1FAC36C2328F36102C2D7D83F43EB5225F0256A871198C61AFD2E4D5D7F5126077BB6E6` |
| TELFHASH | `t103e05540fd388b1a8cd22a74ec8c07b5d8235313212297299f58dae4d83e119a34ce0e` |
| SSDEEP | `3072:MLpvAvzXPG2jMKoq2bo8yvvJWnu1EssMZc/T03ImIys61X1h5ovy7:E6X0KoqWUWEEssMOgh5ove` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_99ed5274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ed5274e7d4abd06e4ce3ee1b893b0d2ed2082f62712fe6fe8e350013f63a5c"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-20 19:59:41"
  condition:
    hash.sha256(0, filesize) == "99ed5274e7d4abd06e4ce3ee1b893b0d2ed2082f62712fe6fe8e350013f63a5c"
}
```

### Sample 82: `cc411feb860ad470`

| Field | Value |
|---|---|
| SHA-256 | `cc411feb860ad470aa97c18ff8169ac2b14537a2e1ac3f29c742096aa1b48b4e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-20 19:59:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `705dd8ce97af99e6b4acbe9ee1c36e54` |
| SHA-1 | `551b0198dfb095fd17c931bad6a0126783003b86` |
| SHA-256 | `cc411feb860ad470aa97c18ff8169ac2b14537a2e1ac3f29c742096aa1b48b4e` |
| SHA3-384 | `72391e25de577a60639b196c2bdcd9969891671d07c33531e64a558cbe0bc9841dd6f37ad9f1447c86c06b9af45b7462` |
| TLSH | `T169C27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:a8vCB+25j6es8RV9FYpMSUpi+20qUpi+20YQX:a8l25Jzd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_cc411feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc411feb860ad470aa97c18ff8169ac2b14537a2e1ac3f29c742096aa1b48b4e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-20 19:59:40"
  condition:
    hash.sha256(0, filesize) == "cc411feb860ad470aa97c18ff8169ac2b14537a2e1ac3f29c742096aa1b48b4e"
}
```

### Sample 83: `3d583585e570b24d`

| Field | Value |
|---|---|
| SHA-256 | `3d583585e570b24deb014343793d57679666390f9123ed38f495414265d99c62` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-20 19:59:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6500c535479923bd72dffecdfcbe4ba` |
| SHA-1 | `fefcdc310581628eebe06381b187315a735c0e01` |
| SHA-256 | `3d583585e570b24deb014343793d57679666390f9123ed38f495414265d99c62` |
| SHA3-384 | `f19c05db42e6c9e93873fcf6c72e3fe29ed9931d27e0e857d53d73ea9a85cc9d239ca7f05fd57da88e37644a7b2e042d` |
| TLSH | `T191236D2526857C14AA99C8371D7E2F0CBDAD43E6320452EE7FCB3CF68C4A69DA10971D` |
| SSDEEP | `768:e6rDTPjHQ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:tr3pcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_3d583585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d583585e570b24deb014343793d57679666390f9123ed38f495414265d99c62"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-20 19:59:38"
  condition:
    hash.sha256(0, filesize) == "3d583585e570b24deb014343793d57679666390f9123ed38f495414265d99c62"
}
```

### Sample 84: `8d538435f6048919`

| Field | Value |
|---|---|
| SHA-256 | `8d538435f6048919c10abd27cf3f1315afeb5c815b6346d0ec9dcfda5afc5b51` |
| Family label | `unknown` |
| File name | `zapret-discord-youtube-1.0.0c.zip` |
| File type | `zip` |
| First seen | `2026-08-20 19:57:04` |
| Reporter | `Alex_sev` |
| Tags | `bat, downloader, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57f01391064cac371eed2be1281070af` |
| SHA-1 | `79e45f117df27c1cffa22b1fc5276d89f9aafe8a` |
| SHA-256 | `8d538435f6048919c10abd27cf3f1315afeb5c815b6346d0ec9dcfda5afc5b51` |
| SHA3-384 | `eea24dd9596b98ba5a85c66eecc58e4e35f0c30222996c938fb55fb133314c13fb4b4da9e5054b9e10f16caf850de7d9` |
| TLSH | `T140653343CC2E429EC71A3837084C692E510377823CEA57B4A75253DCF9AFBA53774A96` |
| SSDEEP | `24576:/cjh9+TiOV9A7D0AtWL+kcatqOCRcKNEiN5GrZP/x7GQrYmILWj:/cL+uUAtWfxtqOQ154P57RrYFLWj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_8d538435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d538435f6048919c10abd27cf3f1315afeb5c815b6346d0ec9dcfda5afc5b51"
    family = "unknown"
    file_name = "zapret-discord-youtube-1.0.0c.zip"
    file_type = "zip"
    first_seen = "2026-08-20 19:57:04"
  condition:
    hash.sha256(0, filesize) == "8d538435f6048919c10abd27cf3f1315afeb5c815b6346d0ec9dcfda5afc5b51"
}
```

### Sample 85: `5a700fc3be720473`

| Field | Value |
|---|---|
| SHA-256 | `5a700fc3be720473411fe7192543ecc18884a787acfd860ec2ad2602755608b5` |
| Family label | `Mirai` |
| File name | `bot.arm7` |
| File type | `elf` |
| First seen | `2026-08-20 19:52:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `834e7ca820bc7cb0765d9e8b606b0dda` |
| SHA-1 | `1fffb9187ae8daff845282992b2c41cb7205b3ca` |
| SHA-256 | `5a700fc3be720473411fe7192543ecc18884a787acfd860ec2ad2602755608b5` |
| SHA3-384 | `c68357636a53f0325f1412b29cae98eb322d52fd13324ee3ea795e9f356f0ab43d59b197ab5c227c37757038c5fddb92` |
| TLSH | `T1F1F31A46A7409B13C4D22BB7EBDF421633239B58D3A72305592CBBF43F8769E4E26506` |
| TELFHASH | `t16e211e25667a982a7e318860ddac9bf25426531763442b32df3fc5dc192b446e52ec0f` |
| SSDEEP | `3072:jsVX7uAzsZaH5WjZKUFR14t3J6vwBhhO0//z/M/9zfKstw2AW:jcuNZaH5WjZKsR1BvChk0//zM/9zf7tl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_5a700fc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a700fc3be720473411fe7192543ecc18884a787acfd860ec2ad2602755608b5"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-20 19:52:21"
  condition:
    hash.sha256(0, filesize) == "5a700fc3be720473411fe7192543ecc18884a787acfd860ec2ad2602755608b5"
}
```

### Sample 86: `2059048a3548f9d3`

| Field | Value |
|---|---|
| SHA-256 | `2059048a3548f9d326a62af7eb3f7da2453a978d13c4049a318ec8a454900875` |
| Family label | `SalatStealer` |
| File name | `windivert.exe` |
| File type | `exe` |
| First seen | `2026-08-20 19:47:19` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73b3ac68da6225e3c5c33cced723ad4c` |
| SHA-1 | `4672fe909b892b43012145b32f3af330f241eea7` |
| SHA-256 | `2059048a3548f9d326a62af7eb3f7da2453a978d13c4049a318ec8a454900875` |
| SHA3-384 | `bf5d85eb4e6dd1261dd9fc229115e833db1b35d08c9c647d44810f8a065ea0b2c168025c8786ea52e01ead13dae48e55` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13BC65C11FACB54F6F9036831416BB27F23315D048B28DB9BEB583B6BF877691186A305` |
| SSDEEP | `98304:WGsqTIVri2C3jGdD4/Logr4i3HVd7EqO/:7Tx3jUDsFrTeqO/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_086_2059048a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2059048a3548f9d326a62af7eb3f7da2453a978d13c4049a318ec8a454900875"
    family = "SalatStealer"
    file_name = "windivert.exe"
    file_type = "exe"
    first_seen = "2026-08-20 19:47:19"
  condition:
    hash.sha256(0, filesize) == "2059048a3548f9d326a62af7eb3f7da2453a978d13c4049a318ec8a454900875"
}
```

### Sample 87: `8f7338402cd66a98`

| Field | Value |
|---|---|
| SHA-256 | `8f7338402cd66a98c73c3fd3da32d2fbcaac7ed83482f538bff433cf8d63d2a5` |
| Family label | `SalatStealer` |
| File name | `windivert.exe` |
| File type | `exe` |
| First seen | `2026-08-20 19:46:37` |
| Reporter | `Alex_sev` |
| Tags | `exe, salat, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d3f36da906eea9cf8a1e013288da4a4` |
| SHA-1 | `47e414f19ad94a79292c8e281ed2589571ac051d` |
| SHA-256 | `8f7338402cd66a98c73c3fd3da32d2fbcaac7ed83482f538bff433cf8d63d2a5` |
| SHA3-384 | `26dd931513020d7090e81fcdcbe02df556fd600873ab6c22c82aeb2b02d3896838140c24ebf58f99c6cc536b7272b2da` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14BF5332F90C8E58FFFEF553FA622D7A0A109C1B7BFC9C9A80D684D4741462ACAF45251` |
| SSDEEP | `98304:4cyenONbsXRFJpo9cB9L79iwvMvSXyCo:TyHNAXMGpMvP` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_087_8f733840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f7338402cd66a98c73c3fd3da32d2fbcaac7ed83482f538bff433cf8d63d2a5"
    family = "SalatStealer"
    file_name = "windivert.exe"
    file_type = "exe"
    first_seen = "2026-08-20 19:46:37"
  condition:
    hash.sha256(0, filesize) == "8f7338402cd66a98c73c3fd3da32d2fbcaac7ed83482f538bff433cf8d63d2a5"
}
```

### Sample 88: `2f916eb6b9a6dd55`

| Field | Value |
|---|---|
| SHA-256 | `2f916eb6b9a6dd550ec623243831b846fe06bea72958316f177f433c02ed6cc5` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-20 19:42:27` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69fdce287ae1a02cfc8df5fbe645051d` |
| SHA-256 | `2f916eb6b9a6dd550ec623243831b846fe06bea72958316f177f433c02ed6cc5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_2f916eb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f916eb6b9a6dd550ec623243831b846fe06bea72958316f177f433c02ed6cc5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 19:42:27"
  condition:
    hash.sha256(0, filesize) == "2f916eb6b9a6dd550ec623243831b846fe06bea72958316f177f433c02ed6cc5"
}
```

### Sample 89: `ad821edb93355775`

| Field | Value |
|---|---|
| SHA-256 | `ad821edb933557752728e1c68d3feb55258c99bb2c544e7a189c580ffe1bb546` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Generic.Dacic.21301.158E32FB.93641826` |
| File type | `exe` |
| First seen | `2026-08-20 19:32:36` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d5e486b948451d889f610190262e46e` |
| SHA-1 | `da1c435b3349a7a284d4511a429fe2df7c50aebf` |
| SHA-256 | `ad821edb933557752728e1c68d3feb55258c99bb2c544e7a189c580ffe1bb546` |
| SHA3-384 | `176cd8e848c7afbd6caa59063928f4feed9fca6e0f206c87436698ed7bb3853b6bcedfb53784a3a64e4aeb1a0d2eb348` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T1B0F4CE04A665B4E8E06644F384D1771DAA66BE0072C05EDA3EDF72716E317E0EDEBE10` |
| SSDEEP | `12288:NVrlSJq5iLFlbWwy8JUFLwxARxAar/nRXvhCY/9mfhhgp1NxYr5Cp46xw/foBVvU:YJqILFUu8pznmU9mfh2pfxYNy46xUB` |
| ICON-DHASH | `78f8bcf2b2b0f059` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_089_ad821edb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad821edb933557752728e1c68d3feb55258c99bb2c544e7a189c580ffe1bb546"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Generic.Dacic.21301.158E32FB.93641826"
    file_type = "exe"
    first_seen = "2026-08-20 19:32:36"
  condition:
    hash.sha256(0, filesize) == "ad821edb933557752728e1c68d3feb55258c99bb2c544e7a189c580ffe1bb546"
}
```

### Sample 90: `dc36090197cd88a4`

| Field | Value |
|---|---|
| SHA-256 | `dc36090197cd88a497bcfb17fe3b89f2cc3a3368941fc95fb89bca0fe0550936` |
| Family label | `unknown` |
| File name | `test.bin` |
| File type | `unknown` |
| First seen | `2026-08-20 19:26:06` |
| Reporter | `iamaachum` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91c53ccccb084da6f5aad71ce48305ee` |
| SHA-256 | `dc36090197cd88a497bcfb17fe3b89f2cc3a3368941fc95fb89bca0fe0550936` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_dc360901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc36090197cd88a497bcfb17fe3b89f2cc3a3368941fc95fb89bca0fe0550936"
    family = "unknown"
    file_name = "test.bin"
    file_type = "unknown"
    first_seen = "2026-08-20 19:26:06"
  condition:
    hash.sha256(0, filesize) == "dc36090197cd88a497bcfb17fe3b89f2cc3a3368941fc95fb89bca0fe0550936"
}
```

### Sample 91: `74c66faabbab048a`

| Field | Value |
|---|---|
| SHA-256 | `74c66faabbab048a567c8550d2cfb9268e61724fb58292a604d44d296777f260` |
| Family label | `unknown` |
| File name | `InstallerV21039x64.exe` |
| File type | `exe` |
| First seen | `2026-08-20 19:21:34` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44a551af59e8f76a426f249bd945cc62` |
| SHA-1 | `3b2d036e8ab48b53226af106267858970203fc06` |
| SHA-256 | `74c66faabbab048a567c8550d2cfb9268e61724fb58292a604d44d296777f260` |
| SHA3-384 | `a2d7028cdeb42212a830604be17b1ba3d6c505f73e6e2dc23cb1bf810c68c514283aa0bdcd9b3f29cf2ec71616ac00ec` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T15EE6339C7CC1986DD9F354B0BE128EAE15E55CEAC104871F2C873BAEF52D629B58340B` |
| SSDEEP | `393216:F4b+oRXgK4CjpVBWwQfgaW+L4B2tOUNKj3rpXNpJoJ:F4b+mXgKv9VD+hW+kkmzxNpJo` |
| ICON-DHASH | `71e8c4f0d4e87092` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_74c66faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c66faabbab048a567c8550d2cfb9268e61724fb58292a604d44d296777f260"
    family = "unknown"
    file_name = "InstallerV21039x64.exe"
    file_type = "exe"
    first_seen = "2026-08-20 19:21:34"
  condition:
    hash.sha256(0, filesize) == "74c66faabbab048a567c8550d2cfb9268e61724fb58292a604d44d296777f260"
}
```

### Sample 92: `f918d79bd0a169fc`

| Field | Value |
|---|---|
| SHA-256 | `f918d79bd0a169fce42a2005b33cf94b2a3d6e227f215a8358a27667fc0320ef` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-08-20 19:21:04` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c54bcc68f387c8f7b8caccb452064e90` |
| SHA-1 | `a28f5286002938412287fd04ece98be88b48a24c` |
| SHA-256 | `f918d79bd0a169fce42a2005b33cf94b2a3d6e227f215a8358a27667fc0320ef` |
| SHA3-384 | `8c4bb672aae82bb4b3fa595db669c577760bebd6d13f725df4ba96db6ed1eca9e3dee88bb49d93390ed5427b62593537` |
| TLSH | `T1C1F633987CC1986DD5F354B0BE128EAE15E65CEAC114871F3C8F3BADF72A219758340A` |
| SSDEEP | `393216:m4b+oRXgK4CjpVBWwQfgaW+L4B2tOUNKj3rpXNpJoJ:m4b+mXgKv9VD+hW+kkmzxNpJo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_f918d79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f918d79bd0a169fce42a2005b33cf94b2a3d6e227f215a8358a27667fc0320ef"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-20 19:21:04"
  condition:
    hash.sha256(0, filesize) == "f918d79bd0a169fce42a2005b33cf94b2a3d6e227f215a8358a27667fc0320ef"
}
```

### Sample 93: `f3d69fda955e715b`

| Field | Value |
|---|---|
| SHA-256 | `f3d69fda955e715bb7ebc418db1e8a21bc5a8e05f38beb879c55087c7e21efb2` |
| Family label | `unknown` |
| File name | `UTODYIBG.msi` |
| File type | `msi` |
| First seen | `2026-08-20 19:14:58` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, HijackLoader, msi, SnappyClient, softwareinformsdk-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b86bb00857035f4dec9518de7623bc4d` |
| SHA-1 | `e3af411d17987883fb4458f6c1ac372606b7adf0` |
| SHA-256 | `f3d69fda955e715bb7ebc418db1e8a21bc5a8e05f38beb879c55087c7e21efb2` |
| SHA3-384 | `2b9bca5db5c9e3e740ca201eae8b1ebfda9a9e6716cf0bb5fc2e1157da74d9086eb3a8a1b14269f484a0d374c91fbd5e` |
| TLSH | `T11A96331D36990B3DCF167DBA54279B00816E2CFC368A877A2E54F2D3B433905799A372` |
| SSDEEP | `196608:z6nI46JZk2z8mCPrNhvAXosm1RaxUHAoAOKDFOj79OW:z6p6J22z8mAHa412OAVF8O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_f3d69fda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3d69fda955e715bb7ebc418db1e8a21bc5a8e05f38beb879c55087c7e21efb2"
    family = "unknown"
    file_name = "UTODYIBG.msi"
    file_type = "msi"
    first_seen = "2026-08-20 19:14:58"
  condition:
    hash.sha256(0, filesize) == "f3d69fda955e715bb7ebc418db1e8a21bc5a8e05f38beb879c55087c7e21efb2"
}
```

### Sample 94: `4dd19ad1b0ab413c`

| Field | Value |
|---|---|
| SHA-256 | `4dd19ad1b0ab413c08b9be29d94623033440affc185bae6a1561f1c0d059a389` |
| Family label | `unknown` |
| File name | `ASUS_thor_2026-08-20_0218.zip` |
| File type | `zip` |
| First seen | `2026-08-20 19:14:44` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1737153823015dca4e28e69b451bce6` |
| SHA-1 | `fa4fd986f712406811de5f709b4dbb809892e392` |
| SHA-256 | `4dd19ad1b0ab413c08b9be29d94623033440affc185bae6a1561f1c0d059a389` |
| SHA3-384 | `96171c14f41a79112a8d8f8fde332ae9c77ca694812758d8924c1c5268cab1bbd2ef3d6ad4a48ad4c700be7bf86ac6cd` |
| TLSH | `T1037423887AA67973CD628C7BE266015092F741882CDDDE539094C5B3F4F4D7832BA9F8` |
| SSDEEP | `6144:eGRlr1JWNsaJh0odIYUOjsExdJ049jL7qmyyZViR9XV5PxVjnRDAzjn0:DghhbCYUOsEni4VLtTZV6FrpVjAA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_4dd19ad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dd19ad1b0ab413c08b9be29d94623033440affc185bae6a1561f1c0d059a389"
    family = "unknown"
    file_name = "ASUS_thor_2026-08-20_0218.zip"
    file_type = "zip"
    first_seen = "2026-08-20 19:14:44"
  condition:
    hash.sha256(0, filesize) == "4dd19ad1b0ab413c08b9be29d94623033440affc185bae6a1561f1c0d059a389"
}
```

### Sample 95: `45e822c1d3c19c73`

| Field | Value |
|---|---|
| SHA-256 | `45e822c1d3c19c7348d676c0a3bdcdd286a6a540687c024c5576084a7f3888ff` |
| Family label | `unknown` |
| File name | `vokal.xml` |
| File type | `unknown` |
| First seen | `2026-08-20 19:13:04` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, HijackLoader, IDATLoader, SnappyClient, softwareinformsdk-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5701f79092712507a46c087b22f24aa1` |
| SHA-256 | `45e822c1d3c19c7348d676c0a3bdcdd286a6a540687c024c5576084a7f3888ff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_45e822c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45e822c1d3c19c7348d676c0a3bdcdd286a6a540687c024c5576084a7f3888ff"
    family = "unknown"
    file_name = "vokal.xml"
    file_type = "unknown"
    first_seen = "2026-08-20 19:13:04"
  condition:
    hash.sha256(0, filesize) == "45e822c1d3c19c7348d676c0a3bdcdd286a6a540687c024c5576084a7f3888ff"
}
```

### Sample 96: `b6f9b9ece65c6e3c`

| Field | Value |
|---|---|
| SHA-256 | `b6f9b9ece65c6e3c15fe362a7e01539058433d3f8d9f6ad78791dc2bf9e6ddfe` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-08-20 19:02:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a40cb59fd08a11970a875d3bdc90446` |
| SHA-1 | `9563fbbf0cf9a9c48a28e15a2f862c558b3ba839` |
| SHA-256 | `b6f9b9ece65c6e3c15fe362a7e01539058433d3f8d9f6ad78791dc2bf9e6ddfe` |
| SHA3-384 | `7a87ff33bdde1b78d3cd88a834313f15d2030de2a820272fd21c334b15a7787fe1fd3f11ba49ffb00f9397a1b0c91bb2` |
| TLSH | `T1CF047CC16DA3E0F1D5534A76526F9B158A36D833022ED611FB6E19387F02620E7AB7CC` |
| TELFHASH | `t1987167f6be760decab905903f74f6722ed0ee67b255026f908f2586032b66019675c38` |
| SSDEEP | `3072:l1sn16sJMprzJy6Oc1t63wshEskDAfcseLanu1EssMZc/T03ImIys61X1h5ob8:bS6sJ83JfhXDs7eLaEEssMOgh5oo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_b6f9b9ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6f9b9ece65c6e3c15fe362a7e01539058433d3f8d9f6ad78791dc2bf9e6ddfe"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-20 19:02:34"
  condition:
    hash.sha256(0, filesize) == "b6f9b9ece65c6e3c15fe362a7e01539058433d3f8d9f6ad78791dc2bf9e6ddfe"
}
```

### Sample 97: `269b7e2e80125edd`

| Field | Value |
|---|---|
| SHA-256 | `269b7e2e80125eddb95d505cd1620779ac2e664ce4a71e6849a06e9f1b459329` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-20 18:52:12` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3fce439ae7e3c80de4f0d1cab1790f6` |
| SHA-256 | `269b7e2e80125eddb95d505cd1620779ac2e664ce4a71e6849a06e9f1b459329` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_269b7e2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "269b7e2e80125eddb95d505cd1620779ac2e664ce4a71e6849a06e9f1b459329"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 18:52:12"
  condition:
    hash.sha256(0, filesize) == "269b7e2e80125eddb95d505cd1620779ac2e664ce4a71e6849a06e9f1b459329"
}
```

### Sample 98: `2c8e0fb0fa2f4533`

| Field | Value |
|---|---|
| SHA-256 | `2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41` |
| Family label | `unknown` |
| File name | `2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41.bin` |
| File type | `exe` |
| First seen | `2026-08-20 18:45:17` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d0b711871bf101562305622ed29eed0` |
| SHA-1 | `ba0dcfb8a1ece3e868f6b03d5f0a28607f9ed8e8` |
| SHA-256 | `2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41` |
| SHA3-384 | `4ce9bce2a4a78fa1e297a232abb2bbfb7bec15011761d6bf0de4fed859c10bf80bd731895ff0f25763e207f3852e0674` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T12618330ABC9945EAC01953334DB616963BB6F8040F7227D32E90F2792EB79E45C7CB58` |
| SSDEEP | `1572864:IMl2lYQoIZ5yl4p1ZGP/J/vmXyQWQt8rbTiGbxUGrKCD2N7p0SlZmtqtwvpkUBu8:I/lgHl4QZGx8XTiG9U5B1ZmkmmZIcNE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_2c8e0fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41"
    family = "unknown"
    file_name = "2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41.bin"
    file_type = "exe"
    first_seen = "2026-08-20 18:45:17"
  condition:
    hash.sha256(0, filesize) == "2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41"
}
```

### Sample 99: `066ecd627caec874`

| Field | Value |
|---|---|
| SHA-256 | `066ecd627caec87426bd94db4f0c1ec45b8345e26b0cace2e8193a91155ce5ee` |
| Family label | `unknown` |
| File name | `packagecache_x64_data.zip` |
| File type | `zip` |
| First seen | `2026-08-20 18:44:56` |
| Reporter | `iamaachum` |
| Tags | `akmuniverstall-top, getintoway-com, OnyxC2, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8590407494ce4ef4bca70d2e3d84ad07` |
| SHA-1 | `214e742c224932cef5fd03ad277597007a983c35` |
| SHA-256 | `066ecd627caec87426bd94db4f0c1ec45b8345e26b0cace2e8193a91155ce5ee` |
| SHA3-384 | `78b51706a4b8825764de3e80f5a5a981c3bf5e66194a6b2918817e00c27cf79497b67254694cf2d5d8d11dbeb806fbef` |
| TLSH | `T1998633D480F2CC6A7D3B836DCDB55652EDD8C60E2605A5FA71A5A20304E77C17BBE22C` |
| SSDEEP | `196608:uIsrmuN8E5OCgewucziS/FFPP8kzKGw1C6AgKnvCvg5OkBarP2:J48E4CgewuMX/zPTzKGw8DQSs2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_066ecd62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "066ecd627caec87426bd94db4f0c1ec45b8345e26b0cace2e8193a91155ce5ee"
    family = "unknown"
    file_name = "packagecache_x64_data.zip"
    file_type = "zip"
    first_seen = "2026-08-20 18:44:56"
  condition:
    hash.sha256(0, filesize) == "066ecd627caec87426bd94db4f0c1ec45b8345e26b0cace2e8193a91155ce5ee"
}
```

### Sample 100: `32f95d8bd1ceef65`

| Field | Value |
|---|---|
| SHA-256 | `32f95d8bd1ceef653e96a49f624efe8b1240f7961a9dd518d786e6892906a170` |
| Family label | `unknown` |
| File name | `Internet Download Manager 6.43 Build 9.exe` |
| File type | `exe` |
| First seen | `2026-08-20 18:44:11` |
| Reporter | `iamaachum` |
| Tags | `akmuniverstall-top, exe, getintoway-com, OnyxC2` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5033c7cd3d1be0a9aad32d25c00c80e` |
| SHA-1 | `8c1edcf321f904c39d80ad1d6b609562f3a737da` |
| SHA-256 | `32f95d8bd1ceef653e96a49f624efe8b1240f7961a9dd518d786e6892906a170` |
| SHA3-384 | `83678887669e58d2d0b6f1402c2f0537b10ba524cfd1e4d1b53738b66693e58a2ea67f3f7ff20e0b3fff2f32a036da4c` |
| IMPHASH | `d61098bb34ea41207b7b575f9f5f033b` |
| TLSH | `T199170121768EC53BF16115F01E2C9AAA921CAD360FA184E773DC7D6E67784C31632E27` |
| SSDEEP | `393216:MxR5WgSinkkOW6CpGqkn/y5c+USn55WZEoaI6SexYIp3Cpn4Z4fkKpwX:sR5WgSi1OW6CpGqW+US5L7geip4ZuwX` |
| ICON-DHASH | `e1e0e6f7e6ed7e38` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_32f95d8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f95d8bd1ceef653e96a49f624efe8b1240f7961a9dd518d786e6892906a170"
    family = "unknown"
    file_name = "Internet Download Manager 6.43 Build 9.exe"
    file_type = "exe"
    first_seen = "2026-08-20 18:44:11"
  condition:
    hash.sha256(0, filesize) == "32f95d8bd1ceef653e96a49f624efe8b1240f7961a9dd518d786e6892906a170"
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
 * Generated: 2026-08-21T02:00:34.750113+00:00
 */

rule MalwareBazaar_unknown_001_c41b729e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c41b729e12c24b609413fa253ba858249d03a61425e00a64ea95fc37f9428a64"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 01:52:10"
  condition:
    hash.sha256(0, filesize) == "c41b729e12c24b609413fa253ba858249d03a61425e00a64ea95fc37f9428a64"
}

rule MalwareBazaar_unknown_002_56369be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56369be9ed5233ecdead1e173e500d990725ae511910c9db5e0dccc4f1b1ae78"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 01:46:07"
  condition:
    hash.sha256(0, filesize) == "56369be9ed5233ecdead1e173e500d990725ae511910c9db5e0dccc4f1b1ae78"
}

rule MalwareBazaar_unknown_003_57ddb41f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57ddb41f77ab8ac66ad2a8a017e7fa768e04052e68783c5683736742152a9271"
    family = "unknown"
    file_name = "lilin.sh"
    file_type = "sh"
    first_seen = "2026-08-21 01:26:48"
  condition:
    hash.sha256(0, filesize) == "57ddb41f77ab8ac66ad2a8a017e7fa768e04052e68783c5683736742152a9271"
}

rule MalwareBazaar_Mirai_004_528778d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "528778d697d92e7c239b16aa532806cc3bd70960bea7ee46156a497a5732ff12"
    family = "Mirai"
    file_name = "bot.ppc"
    file_type = "elf"
    first_seen = "2026-08-21 01:07:27"
  condition:
    hash.sha256(0, filesize) == "528778d697d92e7c239b16aa532806cc3bd70960bea7ee46156a497a5732ff12"
}

rule MalwareBazaar_CoinMiner_005_5d66aefd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d66aefd528ecd9fbd31bf6def4d9f045cbbfd237a3e5e565e9a26feaba45837"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 00:59:13"
  condition:
    hash.sha256(0, filesize) == "5d66aefd528ecd9fbd31bf6def4d9f045cbbfd237a3e5e565e9a26feaba45837"
}

rule MalwareBazaar_unknown_006_bd0cc9da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd0cc9da844d37b34061fe0dad8aa57483401f5d9aa2b078f6bab0f05a0c93e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 00:58:58"
  condition:
    hash.sha256(0, filesize) == "bd0cc9da844d37b34061fe0dad8aa57483401f5d9aa2b078f6bab0f05a0c93e1"
}

rule MalwareBazaar_unknown_007_92ced9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126"
    family = "unknown"
    file_name = "92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:58:23"
  condition:
    hash.sha256(0, filesize) == "92ced9afa998f02baa640c490795419a2e288db47b418e39005bf42ba506b126"
}

rule MalwareBazaar_unknown_008_9c7e0c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7e0c27847e708d05d817b577a1ec06506491b8e99293c206f8b183824ca155"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-21 00:58:21"
  condition:
    hash.sha256(0, filesize) == "9c7e0c27847e708d05d817b577a1ec06506491b8e99293c206f8b183824ca155"
}

rule MalwareBazaar_unknown_009_539881a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054"
    family = "unknown"
    file_name = "539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:57:35"
  condition:
    hash.sha256(0, filesize) == "539881a94db7eeb12740f2789ff1956391803547b709e1a17fb0ce25dfdb5054"
}

rule MalwareBazaar_unknown_010_17fbce07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83"
    family = "unknown"
    file_name = "17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:56:46"
  condition:
    hash.sha256(0, filesize) == "17fbce071aa535131cff4cd5cc2dfacc1b62ee5f907d3a7bcfbb5d51929f4b83"
}

rule MalwareBazaar_unknown_011_ae9eb4f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6"
    family = "unknown"
    file_name = "ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:33"
  condition:
    hash.sha256(0, filesize) == "ae9eb4f844c3fe77ec949b3804042c49c909e5793393f72cd01a66baeaba7af6"
}

rule MalwareBazaar_unknown_012_0a39e22b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a"
    family = "unknown"
    file_name = "0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:29"
  condition:
    hash.sha256(0, filesize) == "0a39e22bbed78a7167dc152ffe2094402a3f6cca342b467fe23c860f706dce1a"
}

rule MalwareBazaar_unknown_013_a2566cc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60"
    family = "unknown"
    file_name = "a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:22"
  condition:
    hash.sha256(0, filesize) == "a2566cc5c500856a3b2cfe7b11a8a6f6997c91f4698a89febcecb8d41905ea60"
}

rule MalwareBazaar_unknown_014_6a85c51a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5"
    family = "unknown"
    file_name = "6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:18"
  condition:
    hash.sha256(0, filesize) == "6a85c51a34bc1007a9ae1f1408881430fd1f6d0942a43e951657aa352a7a97b5"
}

rule MalwareBazaar_unknown_015_5558a2bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f"
    family = "unknown"
    file_name = "5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:14"
  condition:
    hash.sha256(0, filesize) == "5558a2bb032ea66c4da1f9decbd04dbaa7ce58fdda5d3c0b5b14b5a97aa9ca5f"
}

rule MalwareBazaar_unknown_016_71b6be34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070"
    family = "unknown"
    file_name = "71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:08"
  condition:
    hash.sha256(0, filesize) == "71b6be340eb467de63af802826b36ff8103729227dcdf5a71f856409fcc58070"
}

rule MalwareBazaar_unknown_017_a8494348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199"
    family = "unknown"
    file_name = "a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:04"
  condition:
    hash.sha256(0, filesize) == "a84943487aa16c446816e9d161b4aa54fc566d134c0608b76883444fb6cd2199"
}

rule MalwareBazaar_unknown_018_815596f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d"
    family = "unknown"
    file_name = "815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d.elf"
    file_type = "elf"
    first_seen = "2026-08-21 00:53:00"
  condition:
    hash.sha256(0, filesize) == "815596f7c078ce8679408e756db0d206f67cd17237fa6cdc0cfba81d5351382d"
}

rule MalwareBazaar_unknown_019_8c7c5859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7c585913713349d3ffe23cc4f5180f55cfbc01b538200763a86dcf63e2d2bc"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 00:52:11"
  condition:
    hash.sha256(0, filesize) == "8c7c585913713349d3ffe23cc4f5180f55cfbc01b538200763a86dcf63e2d2bc"
}

rule MalwareBazaar_unknown_020_559c37e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "559c37e58a67f08b55c3436e59f906246a1d2d467149a41bddc14818f61b573a"
    family = "unknown"
    file_name = "svvhost.exe"
    file_type = "exe"
    first_seen = "2026-08-21 00:51:21"
  condition:
    hash.sha256(0, filesize) == "559c37e58a67f08b55c3436e59f906246a1d2d467149a41bddc14818f61b573a"
}

rule MalwareBazaar_unknown_021_6162dd76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6162dd763b88e4ca3325960d7870f3eea68cefcc0ccbb97a02f32d00f34c399c"
    family = "unknown"
    file_name = "ReflectiveHVNC64.dll"
    file_type = "exe"
    first_seen = "2026-08-21 00:51:19"
  condition:
    hash.sha256(0, filesize) == "6162dd763b88e4ca3325960d7870f3eea68cefcc0ccbb97a02f32d00f34c399c"
}

rule MalwareBazaar_unknown_022_c1634bbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1634bbe012d27a8a8d6815f750b41c36c5249b79953d5fec6f36e21de1381e4"
    family = "unknown"
    file_name = "HVNC64.dll"
    file_type = "exe"
    first_seen = "2026-08-21 00:51:17"
  condition:
    hash.sha256(0, filesize) == "c1634bbe012d27a8a8d6815f750b41c36c5249b79953d5fec6f36e21de1381e4"
}

rule MalwareBazaar_unknown_023_25f6183c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f6183c81502416d8a5a49457026e69e5e6c31d20d6b3052a1ef56c0c040285"
    family = "unknown"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:45"
  condition:
    hash.sha256(0, filesize) == "25f6183c81502416d8a5a49457026e69e5e6c31d20d6b3052a1ef56c0c040285"
}

rule MalwareBazaar_unknown_024_b246f4ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b246f4efb094d21540a24731186b88e997f88c775416a2ce96b4c54c7ee9d940"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:43"
  condition:
    hash.sha256(0, filesize) == "b246f4efb094d21540a24731186b88e997f88c775416a2ce96b4c54c7ee9d940"
}

rule MalwareBazaar_unknown_025_1d1b1044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d1b10444e55e9b7a0b0aa8ce7bcc3d82e818246b096a954c49ea7750e478dd5"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:42"
  condition:
    hash.sha256(0, filesize) == "1d1b10444e55e9b7a0b0aa8ce7bcc3d82e818246b096a954c49ea7750e478dd5"
}

rule MalwareBazaar_unknown_026_ce890f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce890f43a6545fb0dbd39193364960bb5107b069e8d7fa6e1e31a238ec631d32"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:41"
  condition:
    hash.sha256(0, filesize) == "ce890f43a6545fb0dbd39193364960bb5107b069e8d7fa6e1e31a238ec631d32"
}

rule MalwareBazaar_unknown_027_662a233d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "662a233dbc7d95cc6612526d0f9e43390a95eb4870cd50242b2e64ba2a589202"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:39"
  condition:
    hash.sha256(0, filesize) == "662a233dbc7d95cc6612526d0f9e43390a95eb4870cd50242b2e64ba2a589202"
}

rule MalwareBazaar_unknown_028_c150ee2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c150ee2cfafe6d907ca5b325cf0282a7516a172c6326d730bd4ee8faa716e000"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:38"
  condition:
    hash.sha256(0, filesize) == "c150ee2cfafe6d907ca5b325cf0282a7516a172c6326d730bd4ee8faa716e000"
}

rule MalwareBazaar_unknown_029_ee364d83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee364d83f7c7ae6934283025b999c9b11e83fef527217b879fbf54bbe998b692"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:37"
  condition:
    hash.sha256(0, filesize) == "ee364d83f7c7ae6934283025b999c9b11e83fef527217b879fbf54bbe998b692"
}

rule MalwareBazaar_unknown_030_1385c085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1385c0859e91a4a8492fbc4de56d0c7ea8dbdea77c8c776aaa1ec705dfa96b90"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:36"
  condition:
    hash.sha256(0, filesize) == "1385c0859e91a4a8492fbc4de56d0c7ea8dbdea77c8c776aaa1ec705dfa96b90"
}

rule MalwareBazaar_unknown_031_7681a07c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7681a07ca6e157f8066d8eef5d53afaaedf965aecc43bfade7af4edc5bbe21fd"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:34"
  condition:
    hash.sha256(0, filesize) == "7681a07ca6e157f8066d8eef5d53afaaedf965aecc43bfade7af4edc5bbe21fd"
}

rule MalwareBazaar_unknown_032_df39ed22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:33"
  condition:
    hash.sha256(0, filesize) == "df39ed227704f9d6661ab1c4c598d1cfed90472c6a8e3c75de58b01750382b48"
}

rule MalwareBazaar_unknown_033_f7c770b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7c770b11a493248931a66044ffd4e7e43204e15d3ab29b0f08cd6f74606c6bf"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:32"
  condition:
    hash.sha256(0, filesize) == "f7c770b11a493248931a66044ffd4e7e43204e15d3ab29b0f08cd6f74606c6bf"
}

rule MalwareBazaar_unknown_034_3b382773
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063"
    family = "unknown"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:30"
  condition:
    hash.sha256(0, filesize) == "3b382773c6d6af85d284d0bf38064d761461879bde13269026d8dc88e4977063"
}

rule MalwareBazaar_unknown_035_30db2a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-21 00:18:29"
  condition:
    hash.sha256(0, filesize) == "30db2a6a5946a66c05d900cc7091f466cb9783b56b031fcbaf5f634a7ae435b2"
}

rule MalwareBazaar_unknown_036_1647c36a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1647c36ad4a2f94705eebbd4aff38a6541b9051abf35deb8a8947845b23e2c58"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-21 00:15:26"
  condition:
    hash.sha256(0, filesize) == "1647c36ad4a2f94705eebbd4aff38a6541b9051abf35deb8a8947845b23e2c58"
}

rule MalwareBazaar_RemusStealer_037_7e788bd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e788bd6e7940f7c57dbfd94da87a48b4f36fad48c04a8bb1ba82971317f9023"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 00:03:30"
  condition:
    hash.sha256(0, filesize) == "7e788bd6e7940f7c57dbfd94da87a48b4f36fad48c04a8bb1ba82971317f9023"
}

rule MalwareBazaar_unknown_038_30ef59b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30ef59b648d3e243f641140930a6520f2d6b950defdfb9f41d75953394d88fde"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 23:52:11"
  condition:
    hash.sha256(0, filesize) == "30ef59b648d3e243f641140930a6520f2d6b950defdfb9f41d75953394d88fde"
}

rule MalwareBazaar_Vidar_039_1337ed6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Generic.Dacic.21301.F2A0AC0E.15689265"
    file_type = "exe"
    first_seen = "2026-08-20 23:51:52"
  condition:
    hash.sha256(0, filesize) == "1337ed6fe9c6205b569670a40eab42b51ba69c5c1724d61474e8595acd90ecfb"
}

rule MalwareBazaar_unknown_040_b3cb247a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971"
    family = "unknown"
    file_name = "b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971.exe"
    file_type = "exe"
    first_seen = "2026-08-20 23:26:41"
  condition:
    hash.sha256(0, filesize) == "b3cb247a4848f22cabf9058dd27e73fe4f575a2906ff296b5920b0e9f1bb5971"
}

rule MalwareBazaar_unknown_041_44e7af5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389"
    family = "unknown"
    file_name = "44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389.exe"
    file_type = "exe"
    first_seen = "2026-08-20 23:21:11"
  condition:
    hash.sha256(0, filesize) == "44e7af5e5bd2b34bd8dfe0baddc347ca247091837fbd8ee6a2d4a0a79d339389"
}

rule MalwareBazaar_unknown_042_c4267c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6"
    family = "unknown"
    file_name = "c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6.js"
    file_type = "js"
    first_seen = "2026-08-20 23:12:40"
  condition:
    hash.sha256(0, filesize) == "c4267c66c433f9fe48133c87afaaeaae9db95e0a4a049c5278f347de78de19d6"
}

rule MalwareBazaar_unknown_043_d4051538
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d405153884a919e627f5682af122341b19007c5d1c7ca445642192439cea314d"
    family = "unknown"
    file_name = "bff7503710f200bb.zip"
    file_type = "zip"
    first_seen = "2026-08-20 23:12:16"
  condition:
    hash.sha256(0, filesize) == "d405153884a919e627f5682af122341b19007c5d1c7ca445642192439cea314d"
}

rule MalwareBazaar_unknown_044_3f1ec38d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f1ec38d7dda00155eadc319f52cfec15128ef6a52adc4e97747238a04a68290"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 22:52:10"
  condition:
    hash.sha256(0, filesize) == "3f1ec38d7dda00155eadc319f52cfec15128ef6a52adc4e97747238a04a68290"
}

rule MalwareBazaar_RemusStealer_045_e313c092
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26"
    family = "RemusStealer"
    file_name = "e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26.exe"
    file_type = "exe"
    first_seen = "2026-08-20 22:36:00"
  condition:
    hash.sha256(0, filesize) == "e313c09240d94d6f8aed6e6f4c802f1dce4e204cb7020e72d5344a8cd93b3b26"
}

rule MalwareBazaar_unknown_046_b22207f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b22207f05d3a669d95d750fced07c567733503c2dac83cb599b7b2ab588f8547"
    family = "unknown"
    file_name = "NotaFiscal_Emissao_9512993795129937.zip"
    file_type = "zip"
    first_seen = "2026-08-20 22:19:09"
  condition:
    hash.sha256(0, filesize) == "b22207f05d3a669d95d750fced07c567733503c2dac83cb599b7b2ab588f8547"
}

rule MalwareBazaar_RemusStealer_047_27b521e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af"
    family = "RemusStealer"
    file_name = "27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af.exe"
    file_type = "exe"
    first_seen = "2026-08-20 22:11:27"
  condition:
    hash.sha256(0, filesize) == "27b521e776ee083bfdadc58df6ea8220acb7b0c94340124a00b0c3783ab050af"
}

rule MalwareBazaar_unknown_048_9595ef2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9595ef2ef7db78d3e980077a39b57b167bec665e3f82646ba596bc4da9402ff3"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 21:52:12"
  condition:
    hash.sha256(0, filesize) == "9595ef2ef7db78d3e980077a39b57b167bec665e3f82646ba596bc4da9402ff3"
}

rule MalwareBazaar_CoinMiner_049_fe90b0f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309"
    family = "CoinMiner"
    file_name = "fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309.exe"
    file_type = "exe"
    first_seen = "2026-08-20 21:46:03"
  condition:
    hash.sha256(0, filesize) == "fe90b0f1eb82ff6918fa8bfdf9b3b9b6150ca27fe910f8899241d07a2e57a309"
}

rule MalwareBazaar_Mirai_050_f7223a2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7223a2dd6a1e31d374df80194f141ef33428d757a33bcbecc6b04335d830399"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-20 21:34:18"
  condition:
    hash.sha256(0, filesize) == "f7223a2dd6a1e31d374df80194f141ef33428d757a33bcbecc6b04335d830399"
}

rule MalwareBazaar_unknown_051_e7c5f34d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7c5f34dbbae4d49edee90f7ad98c6e548f50b8c86a9f6ce0b15e49491cafabd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-20 21:09:38"
  condition:
    hash.sha256(0, filesize) == "e7c5f34dbbae4d49edee90f7ad98c6e548f50b8c86a9f6ce0b15e49491cafabd"
}

rule MalwareBazaar_unknown_052_64daa988
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64daa9889c22bf3225dfbb6c4781a2cdfcec5d7a892fa1d517fcfdfd9b2f7582"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-20 21:04:35"
  condition:
    hash.sha256(0, filesize) == "64daa9889c22bf3225dfbb6c4781a2cdfcec5d7a892fa1d517fcfdfd9b2f7582"
}

rule MalwareBazaar_Mirai_053_0fbb8667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fbb8667298388dc86480f23653f085e8ab64a2407f6e38a83f709503f859824"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-20 20:56:26"
  condition:
    hash.sha256(0, filesize) == "0fbb8667298388dc86480f23653f085e8ab64a2407f6e38a83f709503f859824"
}

rule MalwareBazaar_RustyStealer_054_c72c17b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c72c17b0abc3b8c184eafed3e983985016a4b201844425e7009eb00faf96cfbd"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-20 20:54:05"
  condition:
    hash.sha256(0, filesize) == "c72c17b0abc3b8c184eafed3e983985016a4b201844425e7009eb00faf96cfbd"
}

rule MalwareBazaar_unknown_055_47e0d69e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e0d69e42199c1c25dda55d38a5b1469b107621af410eb49617d102750c9503"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 20:52:11"
  condition:
    hash.sha256(0, filesize) == "47e0d69e42199c1c25dda55d38a5b1469b107621af410eb49617d102750c9503"
}

rule MalwareBazaar_Mirai_056_ac06297b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac06297b765ab80aeafe86dec174c114a65e6e3e282c149dddd6179d30fcca88"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-20 20:51:27"
  condition:
    hash.sha256(0, filesize) == "ac06297b765ab80aeafe86dec174c114a65e6e3e282c149dddd6179d30fcca88"
}

rule MalwareBazaar_Vidar_057_c29aba55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29aba55285d4e1a8601261e6c543083b15018b9e5376cc01f267edc71eaea86"
    family = "Vidar"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:50:41"
  condition:
    hash.sha256(0, filesize) == "c29aba55285d4e1a8601261e6c543083b15018b9e5376cc01f267edc71eaea86"
}

rule MalwareBazaar_unknown_058_3304c3a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3304c3a91fdcec91e1fcf846f104d225bf6c3d7097b7b4c2f950f135b9c595ff"
    family = "unknown"
    file_name = "3gaj9IOhsrmr.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:47:29"
  condition:
    hash.sha256(0, filesize) == "3304c3a91fdcec91e1fcf846f104d225bf6c3d7097b7b4c2f950f135b9c595ff"
}

rule MalwareBazaar_Mirai_059_b37f43cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509"
    family = "Mirai"
    file_name = "b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:46:56"
  condition:
    hash.sha256(0, filesize) == "b37f43cdd18ad9b8245273312acf3a92a000a79a8c5ec9be6ff513d30f28a509"
}

rule MalwareBazaar_Mirai_060_7e6a2e24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52"
    family = "Mirai"
    file_name = "7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:46:52"
  condition:
    hash.sha256(0, filesize) == "7e6a2e24a32c7ec72b564c623450e7917dc48bb6948080c0056840a68c39bb52"
}

rule MalwareBazaar_Mirai_061_c3732db4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf"
    family = "Mirai"
    file_name = "c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:46:48"
  condition:
    hash.sha256(0, filesize) == "c3732db414d3db1339c1a0a2088b6ba81acc7dc8ad1eeea4df502b97c15a9dcf"
}

rule MalwareBazaar_unknown_062_c3ddfee0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3ddfee06487de1d376846a072aab90dde7be84c9edf47219eafa3b42fdbd895"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:46:43"
  condition:
    hash.sha256(0, filesize) == "c3ddfee06487de1d376846a072aab90dde7be84c9edf47219eafa3b42fdbd895"
}

rule MalwareBazaar_Mirai_063_5c94555b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333"
    family = "Mirai"
    file_name = "5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:45:59"
  condition:
    hash.sha256(0, filesize) == "5c94555bf53b82433be016759b5d1500692d7f9fc813b7a4ef5c3f4cc9aee333"
}

rule MalwareBazaar_Mirai_064_f5d6944d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5d6944d1133d2b45f1b002172212d72bf3e6e6cb612a42f9f7773bb1bbeec83"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 20:45:25"
  condition:
    hash.sha256(0, filesize) == "f5d6944d1133d2b45f1b002172212d72bf3e6e6cb612a42f9f7773bb1bbeec83"
}

rule MalwareBazaar_AokigaharaStealer_065_39f366b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371"
    family = "AokigaharaStealer"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-20 20:44:49"
  condition:
    hash.sha256(0, filesize) == "39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371"
}

rule MalwareBazaar_Mirai_066_1ce78aa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0"
    family = "Mirai"
    file_name = "1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:43:26"
  condition:
    hash.sha256(0, filesize) == "1ce78aa4c9ff577f5b99bd21b54e0cb2dff3868f3cae8f923bdc7eb9aae116e0"
}

rule MalwareBazaar_Mirai_067_b1a9ae7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609"
    family = "Mirai"
    file_name = "b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:41:04"
  condition:
    hash.sha256(0, filesize) == "b1a9ae7d0b9b6bc29c39d91d9499a87e50ee166dca40b0070c32d2d8cf952609"
}

rule MalwareBazaar_Mirai_068_c479eaa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d"
    family = "Mirai"
    file_name = "c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d.elf"
    file_type = "elf"
    first_seen = "2026-08-20 20:41:00"
  condition:
    hash.sha256(0, filesize) == "c479eaa06b1794ffb433a184d0fcd117a69b9a973e2bfb3c6605ca0c3f6ce11d"
}

rule MalwareBazaar_Mirai_069_9bb80cc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bb80cc73f15beb3ee8272398adfda9f3395cd9a52f82566259a86fb931f39ba"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-20 20:37:49"
  condition:
    hash.sha256(0, filesize) == "9bb80cc73f15beb3ee8272398adfda9f3395cd9a52f82566259a86fb931f39ba"
}

rule MalwareBazaar_Mirai_070_cbbe8bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbbe8baef63751998bb92e30ea1f68b8884c252a3b5447c6ed4b537262f78e3b"
    family = "Mirai"
    file_name = "bot.spc"
    file_type = "elf"
    first_seen = "2026-08-20 20:31:56"
  condition:
    hash.sha256(0, filesize) == "cbbe8baef63751998bb92e30ea1f68b8884c252a3b5447c6ed4b537262f78e3b"
}

rule MalwareBazaar_Mirai_071_79f19dfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f19dfccf9943e58b1c616ef28dd56b816a4aaf8de1370536f649bae236d55e"
    family = "Mirai"
    file_name = "bot.arm5"
    file_type = "elf"
    first_seen = "2026-08-20 20:30:26"
  condition:
    hash.sha256(0, filesize) == "79f19dfccf9943e58b1c616ef28dd56b816a4aaf8de1370536f649bae236d55e"
}

rule MalwareBazaar_Mirai_072_86c27d01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c27d01d30f0bb941e50f4a9c39d4a46cc7a6d325fa44cfd72a908815b1d4b0"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-08-20 20:28:52"
  condition:
    hash.sha256(0, filesize) == "86c27d01d30f0bb941e50f4a9c39d4a46cc7a6d325fa44cfd72a908815b1d4b0"
}

rule MalwareBazaar_Mirai_073_758e750c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "758e750c4c2fb6478b28d0c7d2a6d55eedbb0b5ac65e4795e08eeee472298e3e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-20 20:28:51"
  condition:
    hash.sha256(0, filesize) == "758e750c4c2fb6478b28d0c7d2a6d55eedbb0b5ac65e4795e08eeee472298e3e"
}

rule MalwareBazaar_Mirai_074_cfb3f5de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfb3f5de317afedb369286a65dfee58c47e6b9b58a3ab00bb8ee88395eb72b25"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-08-20 20:27:30"
  condition:
    hash.sha256(0, filesize) == "cfb3f5de317afedb369286a65dfee58c47e6b9b58a3ab00bb8ee88395eb72b25"
}

rule MalwareBazaar_unknown_075_e2edd564
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2edd564b250d9e82c02a7ead600c2022d10f04b4898fe595ecb811a8fb82576"
    family = "unknown"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-20 20:27:28"
  condition:
    hash.sha256(0, filesize) == "e2edd564b250d9e82c02a7ead600c2022d10f04b4898fe595ecb811a8fb82576"
}

rule MalwareBazaar_Mirai_076_1e29360b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e29360b5e4f58062895cac59fa21b55c24f45c2d2d02a52a149787bee0634c1"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-20 20:25:40"
  condition:
    hash.sha256(0, filesize) == "1e29360b5e4f58062895cac59fa21b55c24f45c2d2d02a52a149787bee0634c1"
}

rule MalwareBazaar_Mirai_077_8ce9edf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ce9edf74cedf977fa6e22c2811fd5b8299ecd27fc0d80c7e15272d9b2fbba69"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-20 20:25:38"
  condition:
    hash.sha256(0, filesize) == "8ce9edf74cedf977fa6e22c2811fd5b8299ecd27fc0d80c7e15272d9b2fbba69"
}

rule MalwareBazaar_unknown_078_d634856e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d634856eecdf9465000e435cb8e8f8b57896d69086ed67ddd9a1a990cefc3b50"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-20 20:06:50"
  condition:
    hash.sha256(0, filesize) == "d634856eecdf9465000e435cb8e8f8b57896d69086ed67ddd9a1a990cefc3b50"
}

rule MalwareBazaar_Mirai_079_d3c414ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3c414ea55ff51e39378044996c77cf65c1c2403b8ad232bb8b5c8ee7cadd393"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 20:01:34"
  condition:
    hash.sha256(0, filesize) == "d3c414ea55ff51e39378044996c77cf65c1c2403b8ad232bb8b5c8ee7cadd393"
}

rule MalwareBazaar_Mirai_080_de24c79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de24c79b1a0383bc6afcb7224f273d84207d948c86e84ce4709cdfc5b82a71fb"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-20 20:01:33"
  condition:
    hash.sha256(0, filesize) == "de24c79b1a0383bc6afcb7224f273d84207d948c86e84ce4709cdfc5b82a71fb"
}

rule MalwareBazaar_Mirai_081_99ed5274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ed5274e7d4abd06e4ce3ee1b893b0d2ed2082f62712fe6fe8e350013f63a5c"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-20 19:59:41"
  condition:
    hash.sha256(0, filesize) == "99ed5274e7d4abd06e4ce3ee1b893b0d2ed2082f62712fe6fe8e350013f63a5c"
}

rule MalwareBazaar_unknown_082_cc411feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc411feb860ad470aa97c18ff8169ac2b14537a2e1ac3f29c742096aa1b48b4e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-20 19:59:40"
  condition:
    hash.sha256(0, filesize) == "cc411feb860ad470aa97c18ff8169ac2b14537a2e1ac3f29c742096aa1b48b4e"
}

rule MalwareBazaar_unknown_083_3d583585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d583585e570b24deb014343793d57679666390f9123ed38f495414265d99c62"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-20 19:59:38"
  condition:
    hash.sha256(0, filesize) == "3d583585e570b24deb014343793d57679666390f9123ed38f495414265d99c62"
}

rule MalwareBazaar_unknown_084_8d538435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d538435f6048919c10abd27cf3f1315afeb5c815b6346d0ec9dcfda5afc5b51"
    family = "unknown"
    file_name = "zapret-discord-youtube-1.0.0c.zip"
    file_type = "zip"
    first_seen = "2026-08-20 19:57:04"
  condition:
    hash.sha256(0, filesize) == "8d538435f6048919c10abd27cf3f1315afeb5c815b6346d0ec9dcfda5afc5b51"
}

rule MalwareBazaar_Mirai_085_5a700fc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a700fc3be720473411fe7192543ecc18884a787acfd860ec2ad2602755608b5"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-20 19:52:21"
  condition:
    hash.sha256(0, filesize) == "5a700fc3be720473411fe7192543ecc18884a787acfd860ec2ad2602755608b5"
}

rule MalwareBazaar_SalatStealer_086_2059048a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2059048a3548f9d326a62af7eb3f7da2453a978d13c4049a318ec8a454900875"
    family = "SalatStealer"
    file_name = "windivert.exe"
    file_type = "exe"
    first_seen = "2026-08-20 19:47:19"
  condition:
    hash.sha256(0, filesize) == "2059048a3548f9d326a62af7eb3f7da2453a978d13c4049a318ec8a454900875"
}

rule MalwareBazaar_SalatStealer_087_8f733840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f7338402cd66a98c73c3fd3da32d2fbcaac7ed83482f538bff433cf8d63d2a5"
    family = "SalatStealer"
    file_name = "windivert.exe"
    file_type = "exe"
    first_seen = "2026-08-20 19:46:37"
  condition:
    hash.sha256(0, filesize) == "8f7338402cd66a98c73c3fd3da32d2fbcaac7ed83482f538bff433cf8d63d2a5"
}

rule MalwareBazaar_unknown_088_2f916eb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f916eb6b9a6dd550ec623243831b846fe06bea72958316f177f433c02ed6cc5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 19:42:27"
  condition:
    hash.sha256(0, filesize) == "2f916eb6b9a6dd550ec623243831b846fe06bea72958316f177f433c02ed6cc5"
}

rule MalwareBazaar_Vidar_089_ad821edb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad821edb933557752728e1c68d3feb55258c99bb2c544e7a189c580ffe1bb546"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Generic.Dacic.21301.158E32FB.93641826"
    file_type = "exe"
    first_seen = "2026-08-20 19:32:36"
  condition:
    hash.sha256(0, filesize) == "ad821edb933557752728e1c68d3feb55258c99bb2c544e7a189c580ffe1bb546"
}

rule MalwareBazaar_unknown_090_dc360901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc36090197cd88a497bcfb17fe3b89f2cc3a3368941fc95fb89bca0fe0550936"
    family = "unknown"
    file_name = "test.bin"
    file_type = "unknown"
    first_seen = "2026-08-20 19:26:06"
  condition:
    hash.sha256(0, filesize) == "dc36090197cd88a497bcfb17fe3b89f2cc3a3368941fc95fb89bca0fe0550936"
}

rule MalwareBazaar_unknown_091_74c66faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c66faabbab048a567c8550d2cfb9268e61724fb58292a604d44d296777f260"
    family = "unknown"
    file_name = "InstallerV21039x64.exe"
    file_type = "exe"
    first_seen = "2026-08-20 19:21:34"
  condition:
    hash.sha256(0, filesize) == "74c66faabbab048a567c8550d2cfb9268e61724fb58292a604d44d296777f260"
}

rule MalwareBazaar_unknown_092_f918d79b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f918d79bd0a169fce42a2005b33cf94b2a3d6e227f215a8358a27667fc0320ef"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-20 19:21:04"
  condition:
    hash.sha256(0, filesize) == "f918d79bd0a169fce42a2005b33cf94b2a3d6e227f215a8358a27667fc0320ef"
}

rule MalwareBazaar_unknown_093_f3d69fda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3d69fda955e715bb7ebc418db1e8a21bc5a8e05f38beb879c55087c7e21efb2"
    family = "unknown"
    file_name = "UTODYIBG.msi"
    file_type = "msi"
    first_seen = "2026-08-20 19:14:58"
  condition:
    hash.sha256(0, filesize) == "f3d69fda955e715bb7ebc418db1e8a21bc5a8e05f38beb879c55087c7e21efb2"
}

rule MalwareBazaar_unknown_094_4dd19ad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dd19ad1b0ab413c08b9be29d94623033440affc185bae6a1561f1c0d059a389"
    family = "unknown"
    file_name = "ASUS_thor_2026-08-20_0218.zip"
    file_type = "zip"
    first_seen = "2026-08-20 19:14:44"
  condition:
    hash.sha256(0, filesize) == "4dd19ad1b0ab413c08b9be29d94623033440affc185bae6a1561f1c0d059a389"
}

rule MalwareBazaar_unknown_095_45e822c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45e822c1d3c19c7348d676c0a3bdcdd286a6a540687c024c5576084a7f3888ff"
    family = "unknown"
    file_name = "vokal.xml"
    file_type = "unknown"
    first_seen = "2026-08-20 19:13:04"
  condition:
    hash.sha256(0, filesize) == "45e822c1d3c19c7348d676c0a3bdcdd286a6a540687c024c5576084a7f3888ff"
}

rule MalwareBazaar_Mirai_096_b6f9b9ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6f9b9ece65c6e3c15fe362a7e01539058433d3f8d9f6ad78791dc2bf9e6ddfe"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-20 19:02:34"
  condition:
    hash.sha256(0, filesize) == "b6f9b9ece65c6e3c15fe362a7e01539058433d3f8d9f6ad78791dc2bf9e6ddfe"
}

rule MalwareBazaar_unknown_097_269b7e2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "269b7e2e80125eddb95d505cd1620779ac2e664ce4a71e6849a06e9f1b459329"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-20 18:52:12"
  condition:
    hash.sha256(0, filesize) == "269b7e2e80125eddb95d505cd1620779ac2e664ce4a71e6849a06e9f1b459329"
}

rule MalwareBazaar_unknown_098_2c8e0fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41"
    family = "unknown"
    file_name = "2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41.bin"
    file_type = "exe"
    first_seen = "2026-08-20 18:45:17"
  condition:
    hash.sha256(0, filesize) == "2c8e0fb0fa2f453399d293552496160a7c22caa3f5956d6310fd91caeeb04b41"
}

rule MalwareBazaar_unknown_099_066ecd62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "066ecd627caec87426bd94db4f0c1ec45b8345e26b0cace2e8193a91155ce5ee"
    family = "unknown"
    file_name = "packagecache_x64_data.zip"
    file_type = "zip"
    first_seen = "2026-08-20 18:44:56"
  condition:
    hash.sha256(0, filesize) == "066ecd627caec87426bd94db4f0c1ec45b8345e26b0cace2e8193a91155ce5ee"
}

rule MalwareBazaar_unknown_100_32f95d8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f95d8bd1ceef653e96a49f624efe8b1240f7961a9dd518d786e6892906a170"
    family = "unknown"
    file_name = "Internet Download Manager 6.43 Build 9.exe"
    file_type = "exe"
    first_seen = "2026-08-20 18:44:11"
  condition:
    hash.sha256(0, filesize) == "32f95d8bd1ceef653e96a49f624efe8b1240f7961a9dd518d786e6892906a170"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

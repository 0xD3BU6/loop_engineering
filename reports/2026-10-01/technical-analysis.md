# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-01

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 653 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 653 |
| Unique family labels | 16 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 41 |
| Mirai | 30 |
| VShell | 7 |
| RemcosRAT | 4 |
| AgentTesla | 2 |
| WannaCry | 2 |
| DDoSAgent | 2 |
| CoinMiner | 2 |
| Formbook | 2 |
| GCleaner | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 34 |
| exe | 32 |
| sh | 8 |
| dll | 6 |
| zip | 5 |
| js | 4 |
| apk | 3 |
| vbs | 2 |
| macho | 2 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `64707556ee186bd5`

| Field | Value |
|---|---|
| SHA-256 | `64707556ee186bd56e9f73f70164114b1e55f0448553f7e9c709e0bef42ad834` |
| Family label | `unknown` |
| File name | `payload.sh` |
| File type | `sh` |
| First seen | `2026-10-01 06:04:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `daf83ce7e2e38391a8eda5d0da33c3b2` |
| SHA-1 | `92122d51e3c9bd90c38b8d2aa49387297a50ff35` |
| SHA-256 | `64707556ee186bd56e9f73f70164114b1e55f0448553f7e9c709e0bef42ad834` |
| SHA3-384 | `bee366f5bc0d4435386a7e5a4c83962c027a2df34480ff119d7521ae75052ec24be588833f35a66a005c2e5035d8bc3e` |
| TLSH | `T119D11DF8B431D4713789447FB6688EA4B687D97FA8BC2C40CA86BCD1456DD0938A8377` |
| SSDEEP | `192:oPLwiRLwBJLwj+ULwvItLwvNLww9Lw61LwRbLwV8qdrLwLItLwKb9LwQdLw49Lwh:fX8ogb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_64707556
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64707556ee186bd56e9f73f70164114b1e55f0448553f7e9c709e0bef42ad834"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-10-01 06:04:07"
  condition:
    hash.sha256(0, filesize) == "64707556ee186bd56e9f73f70164114b1e55f0448553f7e9c709e0bef42ad834"
}
```

### Sample 2: `6b4b3724c21b93a7`

| Field | Value |
|---|---|
| SHA-256 | `6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e` |
| Family label | `Mirai` |
| File name | `dbg` |
| File type | `elf` |
| First seen | `2026-10-01 06:04:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f626633cb241ea3eea57f183acad38ff` |
| SHA-1 | `363dede1d55ae0d6a6909a1949ce064b99692fa9` |
| SHA-256 | `6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e` |
| SHA3-384 | `aac495ece0e24449ea0e10d56e1ecaf654e3f522dafd0410d236005b1a1bd0c34c90d4acd6f5ff9aa1960eadd8fda9e8` |
| TLSH | `T164356C2EA2B2F56CE007C03457DFCAA25531B07526323D7B37C59A312EA6DE16359B32` |
| TELFHASH | `t1a9d1ce304df674b0a2d7da01b352f175593218a663f836b51a27bd99ef84f800d6683b` |
| SSDEEP | `12288:fuMxptJwNgUauEVsk4yTjU0cd4Hu3XMMWS2t9GFSTEsehO8Gvb1AbGfUNOayM/aW:fuMxlwNgrKkrTjUH+77GO8Gj6qfUJa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_6b4b3724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-10-01 06:04:05"
  condition:
    hash.sha256(0, filesize) == "6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e"
}
```

### Sample 3: `b28344e12d3576a9`

| Field | Value |
|---|---|
| SHA-256 | `b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b` |
| Family label | `unknown` |
| File name | `b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b.exe` |
| File type | `exe` |
| First seen | `2026-10-01 06:02:39` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `896e834a8ef08553929651b57744c84f` |
| SHA-1 | `0567b28c0897bf718b4e64e0553ebba536df0d56` |
| SHA-256 | `b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b` |
| SHA3-384 | `781a539a119ec5970217137e1e929bbdd54efb05d77315c3f3d043b6c436855f4c1052231cb155d6552c43b64555ff2d` |
| IMPHASH | `f4639a0b3116c2cfc71144b88a929cfd` |
| TLSH | `T145E633527609F160CA5370BB3C1C1EB17B60AA8A5AE426DA75FF5C70FF4CE58828F164` |
| SSDEEP | `196608:GlbuIH1SHcow9j8xRQowx8Ukyde8Jy8skx4j05LskmDhshfWxroff44QKNaK2M3u:GvGYl8DQo4bde7t4skmVufEKNdVf+Tr` |
| ICON-DHASH | `80fcf6bbcaec6430` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_b28344e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b"
    family = "unknown"
    file_name = "b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b.exe"
    file_type = "exe"
    first_seen = "2026-10-01 06:02:39"
  condition:
    hash.sha256(0, filesize) == "b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b"
}
```

### Sample 4: `446150a7841e8574`

| Field | Value |
|---|---|
| SHA-256 | `446150a7841e85746ef4209c550853445d4ff2625242b2f2d62c0c34f30756f8` |
| Family label | `unknown` |
| File name | `db14c885f4ffd5baf2398ec94f529090.exe` |
| File type | `exe` |
| First seen | `2026-10-01 06:01:47` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db14c885f4ffd5baf2398ec94f529090` |
| SHA-1 | `1615d403191dd7034841ea447449ce75aa3089a7` |
| SHA-256 | `446150a7841e85746ef4209c550853445d4ff2625242b2f2d62c0c34f30756f8` |
| SHA3-384 | `dadf486ef32a0e4dd637f31de017bbfef0cd25342a95aaad1f1c095fecd64af5dff16bed919f62f658b537c5aba5ef14` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19764F1042664DEB8D0B91370416ADFB1A3362D067202DB8C5F0671582EE6A563E7FBE7` |
| SSDEEP | `6144:ueigvjj4Dz/ez3zaGPhb1bUYq6OnkUj/W3eJJrp+//qct7t:4cUHeXxhbhqVn5oQ+nq0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_446150a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446150a7841e85746ef4209c550853445d4ff2625242b2f2d62c0c34f30756f8"
    family = "unknown"
    file_name = "db14c885f4ffd5baf2398ec94f529090.exe"
    file_type = "exe"
    first_seen = "2026-10-01 06:01:47"
  condition:
    hash.sha256(0, filesize) == "446150a7841e85746ef4209c550853445d4ff2625242b2f2d62c0c34f30756f8"
}
```

### Sample 5: `a0b056570801f3bc`

| Field | Value |
|---|---|
| SHA-256 | `a0b056570801f3bc3469f3f2f28bd3952fa9e94648797a46656fc16a1fb87303` |
| Family label | `unknown` |
| File name | `DHL MNLR003179244.js` |
| File type | `js` |
| First seen | `2026-10-01 05:56:39` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75586c150bf485d790950ef9b2afdc57` |
| SHA-1 | `93cebf18b69dc68a1013b01b204e2b229dde0f28` |
| SHA-256 | `a0b056570801f3bc3469f3f2f28bd3952fa9e94648797a46656fc16a1fb87303` |
| SHA3-384 | `a0a5a7da6dd6cffa96c4461e89247a605f2c9fdbd741d45f37533d9c7bbe2663c56787ae4824c78d9a84b0367626f220` |
| TLSH | `T1BB465BB57BFF6F4FA9E267EEF68C623F8365A9104C220C2FDA8C12578417425885911F` |
| SSDEEP | `192:Ih+1C++tUrhEK9dO+kmbO6Fyudb6b4S2wIBFfl/x6UvjI7rqS9ONPDMjDNMGUWDW:56Tt0Qbib1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_a0b05657
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0b056570801f3bc3469f3f2f28bd3952fa9e94648797a46656fc16a1fb87303"
    family = "unknown"
    file_name = "DHL MNLR003179244.js"
    file_type = "js"
    first_seen = "2026-10-01 05:56:39"
  condition:
    hash.sha256(0, filesize) == "a0b056570801f3bc3469f3f2f28bd3952fa9e94648797a46656fc16a1fb87303"
}
```

### Sample 6: `b5b7e2731de6384b`

| Field | Value |
|---|---|
| SHA-256 | `b5b7e2731de6384bdd8a82956240cb21e08fc2c8d50cd71dee06823169464ca0` |
| Family label | `unknown` |
| File name | `f286eb73f3fc6ca9aa332bf355e6533b` |
| File type | `dll` |
| First seen | `2026-10-01 05:30:41` |
| Reporter | `AmStaff7021` |
| Tags | `dionaea, dll, exe, honeypot, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f286eb73f3fc6ca9aa332bf355e6533b` |
| SHA-1 | `226fada16070bd7ced493e6d051971616783c3f8` |
| SHA-256 | `b5b7e2731de6384bdd8a82956240cb21e08fc2c8d50cd71dee06823169464ca0` |
| SHA3-384 | `d77d04233d1ec916d490ccc186a12cf77d8fad4ba620ec334fa43c6b9e5ec9b49fb769412ef9e5918bf8141a2f31d436` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T150363358B27CD1BCD20919B458678626A2773C6626FE960FCF5086220D13F29FFE4B47` |
| SSDEEP | `49152:SnAQqMSPbcBVQej/F+TSqTdX1HkQo6SAARdhnvxJM0H9P:+DqPoBhzFcSUDk36SAEdhvxWa9P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_b5b7e273
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5b7e2731de6384bdd8a82956240cb21e08fc2c8d50cd71dee06823169464ca0"
    family = "unknown"
    file_name = "f286eb73f3fc6ca9aa332bf355e6533b"
    file_type = "dll"
    first_seen = "2026-10-01 05:30:41"
  condition:
    hash.sha256(0, filesize) == "b5b7e2731de6384bdd8a82956240cb21e08fc2c8d50cd71dee06823169464ca0"
}
```

### Sample 7: `586d98277d3edc99`

| Field | Value |
|---|---|
| SHA-256 | `586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550` |
| Family label | `unknown` |
| File name | `586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550.exe` |
| File type | `exe` |
| First seen | `2026-10-01 05:28:00` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e35eb70ae56871f566d453ffb98c7a72` |
| SHA-1 | `981f120b98ecc460e1a286890d0a025b2e7facb6` |
| SHA-256 | `586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550` |
| SHA3-384 | `cbed00f744f0639f33470b184e6ef5ba28c47256a973a80dfb621c34997085793e142547d3782bb6cfbd8a0ec0a3ddf0` |
| IMPHASH | `56bfda7073ea0a159d22e925194a7054` |
| TLSH | `T12534495B72A508FBE876823CC4931A05E772B8160761DFAF07A4026A5F237D19D3EF61` |
| SSDEEP | `3072:gju3SbCx1KA8x2frHp8kYyP4tBSOow88TzxqO3MkjvGpPIrSuMuL5IPc3EMgTqA8:gKOCx4vx2syPIgOLHQO3MkixVRCb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_586d9827
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550"
    family = "unknown"
    file_name = "586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:28:00"
  condition:
    hash.sha256(0, filesize) == "586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550"
}
```

### Sample 8: `80bd71812ea7c356`

| Field | Value |
|---|---|
| SHA-256 | `80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25` |
| Family label | `RemusStealer` |
| File name | `80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25.exe` |
| File type | `exe` |
| First seen | `2026-10-01 05:27:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6bb8b8fc06683a0c2244b34cb42dade` |
| SHA-1 | `9e1a6dd1901d1cf6fb262e5ed98f41d6a41185a6` |
| SHA-256 | `80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25` |
| SHA3-384 | `edaf27bb9c5a96182986e51a5641dd0fe1275bce31a14dc0f9c9ea4ae9b096e27cdfa42d2aaefefa2227497b0bd664a3` |
| TLSH | `T1C043392992D543B5D91BC238D9F89367D160F441AA324FEF03D2DD4F1BAB961B20CBA1` |
| SSDEEP | `1536:cSYu6f0qrycmV2RETMJgUvVXkq5iyFz3A9:xYavcE6gkVXkqn93A9` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_008_80bd7181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25"
    family = "RemusStealer"
    file_name = "80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:27:35"
  condition:
    hash.sha256(0, filesize) == "80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25"
}
```

### Sample 9: `6e50beb2039190f8`

| Field | Value |
|---|---|
| SHA-256 | `6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b` |
| Family label | `Mirai` |
| File name | `6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b` |
| File type | `elf` |
| First seen | `2026-10-01 05:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dfd98ffb32b316988e6a294f42b1f75` |
| SHA-1 | `f045684be65dbfc6bc94b1ba30945817a4765884` |
| SHA-256 | `6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b` |
| SHA3-384 | `b9f5a71db1d1a5bad778e72a12ad9cd7bb5750c209b6ea3ffb6b41506669103c6f0130525122b894b364dc9177f5b861` |
| TLSH | `T12EC3089BBC91EE694AC0137BFE2E418E330727B4D1DF71139D141F58B68A94F0E6A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEl:T2s/gAWuboqsJ9xcJxspJBqQgTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_6e50beb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b"
    family = "Mirai"
    file_name = "6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b"
    file_type = "elf"
    first_seen = "2026-10-01 05:17:13"
  condition:
    hash.sha256(0, filesize) == "6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b"
}
```

### Sample 10: `a4adf7d173b6e5b1`

| Field | Value |
|---|---|
| SHA-256 | `a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9` |
| Family label | `unknown` |
| File name | `a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9.exe` |
| File type | `exe` |
| First seen | `2026-10-01 05:14:48` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d205cf6b56e6a81384a67c844fed9067` |
| SHA-1 | `bf745302458b24a6cc6ce4663d260bbe373f4f9b` |
| SHA-256 | `a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9` |
| SHA3-384 | `2bd8cd4aa7d5641597ef87069b1bd3ace1fed86c6a9a19ceebf80cfca103b23ebe445518695e75b058d0dcc7c31e6642` |
| IMPHASH | `b73463e2c02bcc27c18c5f758c7fc511` |
| TLSH | `T16F850753F58ECA22D5720230CFA63A7F9625E1D0774176C70358EC6829663E0F926EDB` |
| SSDEEP | `24576:/CQaKNrvb2zejhrWNVy1y9uVyM9RGWn/oLVqjdKloOPD6:/0mbtroVy1ysyERGWnf5` |
| ICON-DHASH | `4826d8c8c8c83748` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_a4adf7d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9"
    family = "unknown"
    file_name = "a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:14:48"
  condition:
    hash.sha256(0, filesize) == "a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9"
}
```

### Sample 11: `dd50f6da0e5f8d6c`

| Field | Value |
|---|---|
| SHA-256 | `dd50f6da0e5f8d6c8c10df954376162882aa1455e5e501ad4bc71cebc63868a9` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-01 05:14:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b93bacee18f7fb7b813f90883d928a5f` |
| SHA-1 | `e311a6cc570cd410e713f6440a72b6cc8255055a` |
| SHA-256 | `dd50f6da0e5f8d6c8c10df954376162882aa1455e5e501ad4bc71cebc63868a9` |
| SHA3-384 | `98b85fc5233c2705b99983e206d5437167ba3d979e82ce61c409b64eeda0189ae87fe04f90231a0828ab39257878b4ec` |
| TLSH | `T1E1144C01B71D0943E2632EF0373F27D1D3DF9AA125F5EA442A1EBA859271D322585ECE` |
| SSDEEP | `3072:w6vXBlpLYDi3iyjtu0XKB6G4wbx5e5qqnWgDWOKCa2Bq6eHDJA:w6vXDCyBjtY4+xw5qqnWgDWOKh2kJA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_dd50f6da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd50f6da0e5f8d6c8c10df954376162882aa1455e5e501ad4bc71cebc63868a9"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-01 05:14:25"
  condition:
    hash.sha256(0, filesize) == "dd50f6da0e5f8d6c8c10df954376162882aa1455e5e501ad4bc71cebc63868a9"
}
```

### Sample 12: `0dc9d5b5d7b478e8`

| Field | Value |
|---|---|
| SHA-256 | `0dc9d5b5d7b478e8fd56f0794c21a1b1e3b09cd47d766c7779c301aa71c8ef33` |
| Family label | `Mirai` |
| File name | `7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf.elf` |
| File type | `elf` |
| First seen | `2026-10-01 05:14:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0180b03f66aaf707dc76ecafc689f34e` |
| SHA-1 | `f93a216496762629c3d15117fa56838ea8b4a1ae` |
| SHA-256 | `0dc9d5b5d7b478e8fd56f0794c21a1b1e3b09cd47d766c7779c301aa71c8ef33` |
| SHA3-384 | `73bf8a707e9574d3c6926a94ecaadfc1ed02e05b6e73f49c69dae52ae93d19141959d48b9b25e81d5cfbdc13989b351a` |
| TLSH | `T184E32B46F6418B13C5D61777FAAF414A3322D794A3DB330699285BF43F86A9F0E13A06` |
| TELFHASH | `t1b4219bb1572aa6245969cbec89dc73b9122c86121247df33ef2184bca41949df525c4f` |
| SSDEEP | `3072:5IvM9qqxuvV8yAzltJXu9CttQJ2Ed83zGCzFX0clM/9REw/kP:mvM9qqxuvV8yAzYaQJ2EduGSX0aM/9pO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_0dc9d5b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc9d5b5d7b478e8fd56f0794c21a1b1e3b09cd47d766c7779c301aa71c8ef33"
    family = "Mirai"
    file_name = "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf.elf"
    file_type = "elf"
    first_seen = "2026-10-01 05:14:22"
  condition:
    hash.sha256(0, filesize) == "0dc9d5b5d7b478e8fd56f0794c21a1b1e3b09cd47d766c7779c301aa71c8ef33"
}
```

### Sample 13: `db02b4218c861714`

| Field | Value |
|---|---|
| SHA-256 | `db02b4218c861714def17679d47d00ff0287b9100839a6fdc27b58562cdd45f3` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-01 05:14:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3fcc97deec4ebec298894b39b31ec9f` |
| SHA-1 | `8c704f1c2047cd2e51ee661952c640aae57e8260` |
| SHA-256 | `db02b4218c861714def17679d47d00ff0287b9100839a6fdc27b58562cdd45f3` |
| SHA3-384 | `aaf9a33da4059bd56ff6b9d9e5d639f4b88d019d2c9bd9737fa213524448d25692a9f2d0eb30d4ac47d47c959a2f1645` |
| TLSH | `T1EB730264C4D51E00DF6BEAFCDFF5974897F7E6649ABA863126DA23027044CC92803EE5` |
| SSDEEP | `1536:np+Xyk6a/Weqs0rXk0GLEebVVAbMpzkHwHX6vDFoPw2X4u+qgw09Q:g6reD0rOjS8Ow3aSPH4u+qgwB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_db02b421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db02b4218c861714def17679d47d00ff0287b9100839a6fdc27b58562cdd45f3"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-01 05:14:14"
  condition:
    hash.sha256(0, filesize) == "db02b4218c861714def17679d47d00ff0287b9100839a6fdc27b58562cdd45f3"
}
```

### Sample 14: `7e9a7d470aaad743`

| Field | Value |
|---|---|
| SHA-256 | `7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf` |
| Family label | `Mirai` |
| File name | `7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf.elf` |
| File type | `elf` |
| First seen | `2026-10-01 05:13:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f52a6e6fee0803c365e4bf0bd3e6a9e` |
| SHA-1 | `a5273bed84e75da24bcc346007799a332da940d9` |
| SHA-256 | `7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf` |
| SHA3-384 | `a8ef982ebf3a17448b3f5b15682597bfa2d75f2c4ba625526ad072e973ccacad1d1aef4586b83ebaf47673c8dc574a8c` |
| TLSH | `T140330223B744BD62DE761D3972F88D8B3148466ED4ECA82235C8996163C314BFBD45D3` |
| SSDEEP | `768:hfZYvZxNZ/SPjiUv0w0zyIvfgJy2LHRfb/taD9q3UEL2qEK5J6OAsNTGjf2tl8Xa:CPtQjiZVcykHRDl7L15J6RN2tAa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_7e9a7d47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf"
    family = "Mirai"
    file_name = "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf.elf"
    file_type = "elf"
    first_seen = "2026-10-01 05:13:59"
  condition:
    hash.sha256(0, filesize) == "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf"
}
```

### Sample 15: `dbb93fb26bf429a7`

| Field | Value |
|---|---|
| SHA-256 | `dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916` |
| Family label | `unknown` |
| File name | `dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916.exe` |
| File type | `exe` |
| First seen | `2026-10-01 05:13:11` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b28ca70a8fb8187796c8e81e2687c06e` |
| SHA-1 | `fb017af7247f9ba558c28e038ff8186be624678f` |
| SHA-256 | `dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916` |
| SHA3-384 | `e1e522c6e437d6a50b87108531f23deb559d960afdd6d6750e88865235421499453ce8aa210fde9bf1480e2724536254` |
| IMPHASH | `bae3d3e8262d7ce7e9ee69cc1b630d3a` |
| TLSH | `T18386339AB3A109F9D92340BCC082D865FA72B8771778D68B03F595D72F83991683EF11` |
| SSDEEP | `98304:pn98OzNPfjJVS27wy4Pf1N2zIh3ET949MxVMOPUh3PdWPEUrJY6TOxbHpvmJ1nl+:pn9LPbL4FMIZETSwjPePdrQJyBsnlnc` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_dbb93fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916"
    family = "unknown"
    file_name = "dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:13:11"
  condition:
    hash.sha256(0, filesize) == "dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916"
}
```

### Sample 16: `e1b30def98704eda`

| Field | Value |
|---|---|
| SHA-256 | `e1b30def98704eda7ca2abb7aea902cdc98be471fe3ace60e6017e1588413363` |
| Family label | `AgentTesla` |
| File name | `statement-103217.js` |
| File type | `js` |
| First seen | `2026-10-01 05:13:06` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21d3baafbd8b2b623262ab09b912f2ef` |
| SHA-1 | `86f46101026d2db833b989be18577436dc824941` |
| SHA-256 | `e1b30def98704eda7ca2abb7aea902cdc98be471fe3ace60e6017e1588413363` |
| SHA3-384 | `206342416f6e100990ac90e223894a10bf16c8fda17ef9678d77da0d322683136e2b62e70d9548287ed6dce3c6198a70` |
| TLSH | `T13DE4D0A539C8E6D8841E3B161B17374C46B11AB9D6C9DAC5C419DE8D2231A73CAFECCC` |
| SSDEEP | `12288:Q78zwfZg2YR7aqR3ZyI8KpzF3yg3s20GyIEOYOtkPV8/GN0qOC7xB:qa2YR2i3ZyIlmg8mzYPZNz` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_016_e1b30def
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1b30def98704eda7ca2abb7aea902cdc98be471fe3ace60e6017e1588413363"
    family = "AgentTesla"
    file_name = "statement-103217.js"
    file_type = "js"
    first_seen = "2026-10-01 05:13:06"
  condition:
    hash.sha256(0, filesize) == "e1b30def98704eda7ca2abb7aea902cdc98be471fe3ace60e6017e1588413363"
}
```

### Sample 17: `1c93d7059eed451f`

| Field | Value |
|---|---|
| SHA-256 | `1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d` |
| Family label | `VShell` |
| File name | `1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d.exe` |
| File type | `exe` |
| First seen | `2026-10-01 05:12:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56ad67a8a2c62ad6cfeae535c9ccc21e` |
| SHA-1 | `d4a6536f68144dc4a39bb0aeebccfed5ac3093ce` |
| SHA-256 | `1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d` |
| SHA3-384 | `cc327bbd47127eff5541602ac3cf6bed11f7a92ebfab39fb58a127cbc2d6f5abbfd9148f26d092646bd0d8d71dddd644` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T19391A5C5F757E6B6EC1C07F500A379A4C8682E14927C9B568FE16F0C3C111AA3D2EA52` |
| SSDEEP | `48:6I7lwe7MV08SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1m091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_017_1c93d705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d"
    family = "VShell"
    file_name = "1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:12:45"
  condition:
    hash.sha256(0, filesize) == "1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d"
}
```

### Sample 18: `7250576a3cb7164b`

| Field | Value |
|---|---|
| SHA-256 | `7250576a3cb7164bf383d89683267604dd1a5d36e1a35f22b5bef2d9f29402e5` |
| Family label | `RemcosRAT` |
| File name | `(TWN26100200.TWN26100218.TWN26100222.TWN26090662.TWN26100226.TWN26100262.TWN26100313).exe` |
| File type | `exe` |
| First seen | `2026-10-01 04:43:23` |
| Reporter | `threatcat_ch` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7ae6bfb61ecc81b5425c311f050a518` |
| SHA-1 | `3872008acee3624bf9a290fe384e399958973acd` |
| SHA-256 | `7250576a3cb7164bf383d89683267604dd1a5d36e1a35f22b5bef2d9f29402e5` |
| SHA3-384 | `7ea48ab260c8fccab76e9e098af9e4ebbe1d93f1661f90dcceacb1d31286d95d9177999cfb3b0440e69bf68facb24de6` |
| TLSH | `T1DD4502186A5BEC03C8B503358AE2F6B043F56E4DE522D25B8FEA2CDB3921BD519D4353` |
| SSDEEP | `24576:cWViPkKzZl+cccZK8pn/TboYll5tFhh3pQ4+6oOF6uraCDB:ckisKzZlfccZxpLboYZtFb3aZMDB` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_018_7250576a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7250576a3cb7164bf383d89683267604dd1a5d36e1a35f22b5bef2d9f29402e5"
    family = "RemcosRAT"
    file_name = "(TWN26100200.TWN26100218.TWN26100222.TWN26090662.TWN26100226.TWN26100262.TWN26100313).exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:43:23"
  condition:
    hash.sha256(0, filesize) == "7250576a3cb7164bf383d89683267604dd1a5d36e1a35f22b5bef2d9f29402e5"
}
```

### Sample 19: `da9bb5422c3fc73f`

| Field | Value |
|---|---|
| SHA-256 | `da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc` |
| Family label | `unknown` |
| File name | `da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc.exe` |
| File type | `exe` |
| First seen | `2026-10-01 04:42:43` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eefd7d931e81ee82f42942cf034d9422` |
| SHA-1 | `f9db44671bdb0c4a0beb5656ee6bc741a49019c1` |
| SHA-256 | `da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc` |
| SHA3-384 | `b581359ae9f15a8f3ac51179e779ded463f7acab1297fd20f5d7442196c0629fda8567872703d5f906df16a67ed57f00` |
| IMPHASH | `54420143057cda58267e1f513b321387` |
| TLSH | `T17203389E72D044FCD866C135DAFAC3369871FCA81974166E1768CA3A2F709B0573960B` |
| SSDEEP | `384:7DDLLEXmoDf2Mu0eLGNOwi58r/HhNf2QEJB5d9OAQh5fRFk+98SWRLWxCW:73smYY0Bi52/DK/5d9OAQhdR688VzW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_da9bb542
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc"
    family = "unknown"
    file_name = "da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:42:43"
  condition:
    hash.sha256(0, filesize) == "da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc"
}
```

### Sample 20: `7c77f80c4cb795f8`

| Field | Value |
|---|---|
| SHA-256 | `7c77f80c4cb795f8d19a1c90340ff39012c1617d8b4f7cfe7cb3b8f7a14521c8` |
| Family label | `unknown` |
| File name | `mbupload-0o19xzqz.bin` |
| File type | `sh` |
| First seen | `2026-10-01 04:42:17` |
| Reporter | `wristhulk` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b899b991709f923501c2037edbff89ba` |
| SHA-1 | `6a72f38affc097ab75f8af6d93f108069600191c` |
| SHA-256 | `7c77f80c4cb795f8d19a1c90340ff39012c1617d8b4f7cfe7cb3b8f7a14521c8` |
| SHA3-384 | `a64bc4898af55e05b45dd921e85ce36a10694ab0c6954e74b2a4fcdcf8f49612302ca32bd38d76d913cd44cd1a4ec966` |
| TLSH | `T12101C2AAF0614332745C147DF617B7811E83682F18F47C94B4553C61BD9C916B076B11` |
| SSDEEP | `24:QXTP6DDHJJV6F7X3E8EeOC3E8F0T6DTxCtM:6cDHJJUo8Lu8Kcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_7c77f80c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c77f80c4cb795f8d19a1c90340ff39012c1617d8b4f7cfe7cb3b8f7a14521c8"
    family = "unknown"
    file_name = "mbupload-0o19xzqz.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:17"
  condition:
    hash.sha256(0, filesize) == "7c77f80c4cb795f8d19a1c90340ff39012c1617d8b4f7cfe7cb3b8f7a14521c8"
}
```

### Sample 21: `90c930f706880abf`

| Field | Value |
|---|---|
| SHA-256 | `90c930f706880abf2b7b6da83c694884ef4852716c6af24aa6c636a830d05617` |
| Family label | `unknown` |
| File name | `mbupload-dyugeu5n.bin` |
| File type | `sh` |
| First seen | `2026-10-01 04:42:13` |
| Reporter | `wristhulk` |
| Tags | `downloader, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cced002f900545719e0a86fa7d8c9bb` |
| SHA-1 | `7d695e07944e204ec65c0c05272cdebceb9d02e3` |
| SHA-256 | `90c930f706880abf2b7b6da83c694884ef4852716c6af24aa6c636a830d05617` |
| SHA3-384 | `adaf82c0c8c1bd0c5a530fd7c95d8064f07a5a6cb7356baeab32a823066d3d73251ccb4fda6fe80dbec430d099beb669` |
| TLSH | `T17C51F18679A3D53783FB99605F43A301E792118308939498B49DED333FFA041FDA5E5A` |
| SSDEEP | `48:/NldnxZ8m0S1efrZvmby8WMYBELQJbKMgS9Nul4KWzv:VldxZ8m0ffrZObyBbbKMgQzv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_90c930f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90c930f706880abf2b7b6da83c694884ef4852716c6af24aa6c636a830d05617"
    family = "unknown"
    file_name = "mbupload-dyugeu5n.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:13"
  condition:
    hash.sha256(0, filesize) == "90c930f706880abf2b7b6da83c694884ef4852716c6af24aa6c636a830d05617"
}
```

### Sample 22: `2408a722990b8131`

| Field | Value |
|---|---|
| SHA-256 | `2408a722990b81312752796ff89b8e3660421f8c09bdd9fe2bf412a9bb89ce3f` |
| Family label | `unknown` |
| File name | `mbupload-rmslsmtw.bin` |
| File type | `sh` |
| First seen | `2026-10-01 04:42:07` |
| Reporter | `wristhulk` |
| Tags | `downloader, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d4d5035c887d26ffff930355e567804` |
| SHA-1 | `31bb3539ffa18efefbc20074e324d53d26e4db4e` |
| SHA-256 | `2408a722990b81312752796ff89b8e3660421f8c09bdd9fe2bf412a9bb89ce3f` |
| SHA3-384 | `1694c9fb17c551c4b9cebac12a1492882e35ffdd58090d5e894e1ee5e22882c1221e079d652ab21bc77279218ee8dced` |
| TLSH | `T1663163DE0011AA305103CE4E7776318D664EE2EB289FDBE499480EDA53887DCF265F4D` |
| SSDEEP | `12:U7I67IMo0760Hh91i61sUomff6G6wDX9n6N7BiH6BiO3vVQR776/GGaV6a3EAbr9:uLICvBDf11fVDXUn9NQQGVHlBbPyK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_2408a722
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2408a722990b81312752796ff89b8e3660421f8c09bdd9fe2bf412a9bb89ce3f"
    family = "unknown"
    file_name = "mbupload-rmslsmtw.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:07"
  condition:
    hash.sha256(0, filesize) == "2408a722990b81312752796ff89b8e3660421f8c09bdd9fe2bf412a9bb89ce3f"
}
```

### Sample 23: `a330fdc4266c2163`

| Field | Value |
|---|---|
| SHA-256 | `a330fdc4266c2163a661aab758c06d52de0e923872dfb95f16f371183d4280f0` |
| Family label | `unknown` |
| File name | `mbupload-r7gxy7lq.bin` |
| File type | `sh` |
| First seen | `2026-10-01 04:42:01` |
| Reporter | `wristhulk` |
| Tags | `downloader, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a469a528c0f2bc4caada3bd98751934` |
| SHA-1 | `3278d490f6a0dd689958bff8a0296d33fdc670da` |
| SHA-256 | `a330fdc4266c2163a661aab758c06d52de0e923872dfb95f16f371183d4280f0` |
| SHA3-384 | `6dbb5d1078313337e6a30fe3055cbd50e6114640dfcdff603a42bfa711b1703f007185dd39fa84d10abe7fcde5f33769` |
| TLSH | `T1D831629F46206A795202CADD777B395C700C81EB285BD794DC4C5EED82891DC72B1FCA` |
| SSDEEP | `24:tKyDfc1+01yLmtU4dQ7lGp3N6+0XdGW69ewRwf2Hvn:tKAfNLQ4RK3N6ZXJeDn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_a330fdc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a330fdc4266c2163a661aab758c06d52de0e923872dfb95f16f371183d4280f0"
    family = "unknown"
    file_name = "mbupload-r7gxy7lq.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:01"
  condition:
    hash.sha256(0, filesize) == "a330fdc4266c2163a661aab758c06d52de0e923872dfb95f16f371183d4280f0"
}
```

### Sample 24: `371188405bfded45`

| Field | Value |
|---|---|
| SHA-256 | `371188405bfded45d2b7d0259c204611064d3bb4da5364ed70ce1b33e0f70fff` |
| Family label | `unknown` |
| File name | `mbupload-_os2ruh8.bin` |
| File type | `sh` |
| First seen | `2026-10-01 04:41:54` |
| Reporter | `wristhulk` |
| Tags | `downloader, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `568ad9be7eff24105ee6c601c551dcf4` |
| SHA-1 | `6d515b2868662d03609abe061fdd1797f69bdcba` |
| SHA-256 | `371188405bfded45d2b7d0259c204611064d3bb4da5364ed70ce1b33e0f70fff` |
| SHA3-384 | `dce019c3b21b4d17ec30db1ba6173a640a14105595a6e46773bc25302c7a070c8ab1ddbc0e908ad0d6434b7faac5b7a9` |
| TLSH | `T16BF03085FF04EA776407DE5733A803305747B8FAA4C30256AC627D9A1CC8AC97406EB5` |
| SSDEEP | `6:IOnFflR0mvwPn2GvwNNd9UFovwiGvw59UFovwRE2GvwRg9t:IPn27fdii75il7aX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_37118840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "371188405bfded45d2b7d0259c204611064d3bb4da5364ed70ce1b33e0f70fff"
    family = "unknown"
    file_name = "mbupload-_os2ruh8.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:41:54"
  condition:
    hash.sha256(0, filesize) == "371188405bfded45d2b7d0259c204611064d3bb4da5364ed70ce1b33e0f70fff"
}
```

### Sample 25: `098a85921ef63f60`

| Field | Value |
|---|---|
| SHA-256 | `098a85921ef63f6076c18316d8437759f7c143794f4f4bf53901db1a12fac728` |
| Family label | `unknown` |
| File name | `mbupload-zhpskrdh.bin` |
| File type | `sh` |
| First seen | `2026-10-01 04:41:48` |
| Reporter | `wristhulk` |
| Tags | `downloader, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af1c391023498713fbea2c3937d5e499` |
| SHA-1 | `8a69a96a917a226c1e4eada9cdfc30578af9cbbb` |
| SHA-256 | `098a85921ef63f6076c18316d8437759f7c143794f4f4bf53901db1a12fac728` |
| SHA3-384 | `e936e01390a04aa0a58e9b0e35f2e0387500d8811603a985efa2ce98804119def58a887e88729e7c4dc9713124b6b607` |
| TLSH | `T1BD51A29B13984B35964E858EB7F03534A14AB9D3BAEBC614EA50383C0EC9D9C32C5FC0` |
| SSDEEP | `24:Lu2JMZzbiBh+uZ4EzEnE2EhEy5rbwiBJUfu5hM3G:Lu2JMZzbiBh+uZ44cvyrrbwi5hM3G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_098a8592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "098a85921ef63f6076c18316d8437759f7c143794f4f4bf53901db1a12fac728"
    family = "unknown"
    file_name = "mbupload-zhpskrdh.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:41:48"
  condition:
    hash.sha256(0, filesize) == "098a85921ef63f6076c18316d8437759f7c143794f4f4bf53901db1a12fac728"
}
```

### Sample 26: `519c0a6541692082`

| Field | Value |
|---|---|
| SHA-256 | `519c0a6541692082d0b71d12bd582128b20c8fe9541be676ee2ebe389943830a` |
| Family label | `unknown` |
| File name | `mbupload-xc0atw_0.bin` |
| File type | `sh` |
| First seen | `2026-10-01 04:41:42` |
| Reporter | `wristhulk` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d64d596cd08fcece3a9b6bfb79a32cf` |
| SHA-1 | `32074d65921ae6bb79120801ba7657b5efe3196e` |
| SHA-256 | `519c0a6541692082d0b71d12bd582128b20c8fe9541be676ee2ebe389943830a` |
| SHA3-384 | `888d86cd44100ba73fc1608f8e0dce5eec3e401d8c05df8557067d9f04c1a20a4a354d39a6f47279276c702f83d8d8bc` |
| TLSH | `T1ED21EDF8B9708D113A5A457D385E4894AAC7883F489A3C94B84E99322F4D20DF05AB7E` |
| SSDEEP | `24:/iOEfggG4SifU9pUh5ADou+Fs69UcKP6JQQUUZT//PkE7bEYcj:6FIEF89Sh5/u+G62cM6JQQNVPkEnEYcj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_519c0a65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "519c0a6541692082d0b71d12bd582128b20c8fe9541be676ee2ebe389943830a"
    family = "unknown"
    file_name = "mbupload-xc0atw_0.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:41:42"
  condition:
    hash.sha256(0, filesize) == "519c0a6541692082d0b71d12bd582128b20c8fe9541be676ee2ebe389943830a"
}
```

### Sample 27: `256fff3dae1bb819`

| Field | Value |
|---|---|
| SHA-256 | `256fff3dae1bb819c8b21fdc807795c3301354797ed8714b363e532c8602a94e` |
| Family label | `unknown` |
| File name | `mbupload-nobkugyv.bin` |
| File type | `dll` |
| First seen | `2026-10-01 04:41:37` |
| Reporter | `wristhulk` |
| Tags | `dll, downloader, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57a71607bb704159d230dda1e0ff0147` |
| SHA-1 | `21b9080a69c773abc4717252b4aaa992a048ba8a` |
| SHA-256 | `256fff3dae1bb819c8b21fdc807795c3301354797ed8714b363e532c8602a94e` |
| SHA3-384 | `52f0e45719cbb815a7d699b4779d2d6dd7d706980499dd3083440ffec4c06d4e694a262793f121a299518fd9dafc0be0` |
| IMPHASH | `f9b3cce3de2e9e78aa0cd0519c7ab711` |
| TLSH | `T17C633A1572968037E9F7267C0EFEA33183AF7880877561D764C81BEE9BB02D15A38356` |
| SSDEEP | `768:a8O6iuBiWMeSTM7lhtFS5oLIpTlG+8+aYHdRP9tshsGw8U4hHNEDQ4F4iNx5i:a16iuzMeSTQF3nKaY9RsE8UaBs5i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_256fff3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "256fff3dae1bb819c8b21fdc807795c3301354797ed8714b363e532c8602a94e"
    family = "unknown"
    file_name = "mbupload-nobkugyv.bin"
    file_type = "dll"
    first_seen = "2026-10-01 04:41:37"
  condition:
    hash.sha256(0, filesize) == "256fff3dae1bb819c8b21fdc807795c3301354797ed8714b363e532c8602a94e"
}
```

### Sample 28: `22618abc5d61041a`

| Field | Value |
|---|---|
| SHA-256 | `22618abc5d61041a92b4ba1b15742f09d8d43630df249395b5d7c4df8a1112aa` |
| Family label | `WannaCry` |
| File name | `mbupload-tl8tzsiz.bin` |
| File type | `dll` |
| First seen | `2026-10-01 04:41:31` |
| Reporter | `wristhulk` |
| Tags | `dll, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4cc9844574dec633d8adc474215159c` |
| SHA-1 | `e775edc6f2765cdf2c0002e3c0a5ce42551e6b3d` |
| SHA-256 | `22618abc5d61041a92b4ba1b15742f09d8d43630df249395b5d7c4df8a1112aa` |
| SHA3-384 | `f168e5ed0791b99fc951fd44ecf6a2a1a8f7c90231c6742050c1ce547094f52a15d2c1cc10ff399a34ba384558adbada` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T13B360214FFD88AB1C56A12344DB382306F7FF85497A5830BD3B4AA792C277589F64E81` |
| SSDEEP | `49152:SnAQqMSPbcBVQej/1IbARdhnvxJM0H9JVeiC9avc:+DqPoBhz1AEdhvxWa9LeP` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_028_22618abc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22618abc5d61041a92b4ba1b15742f09d8d43630df249395b5d7c4df8a1112aa"
    family = "WannaCry"
    file_name = "mbupload-tl8tzsiz.bin"
    file_type = "dll"
    first_seen = "2026-10-01 04:41:31"
  condition:
    hash.sha256(0, filesize) == "22618abc5d61041a92b4ba1b15742f09d8d43630df249395b5d7c4df8a1112aa"
}
```

### Sample 29: `1e4b319e9aaa514a`

| Field | Value |
|---|---|
| SHA-256 | `1e4b319e9aaa514af9a0ca9b31bae004b8d5a77e9a6aa5edcd957025872710ba` |
| Family label | `WannaCry` |
| File name | `mbupload-vq31wrg6.bin` |
| File type | `dll` |
| First seen | `2026-10-01 04:41:23` |
| Reporter | `wristhulk` |
| Tags | `dll, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33549e75d439945d1b6a415732c98519` |
| SHA-1 | `6a9fbe9256f9d09b3654695d151e29283c9762c2` |
| SHA-256 | `1e4b319e9aaa514af9a0ca9b31bae004b8d5a77e9a6aa5edcd957025872710ba` |
| SHA3-384 | `7c29018823be9242b3ba05c238ca2021236a705a8f4883d48427271b13b3c7dafdebc4610f0b38af071aca7b0a8c73ee` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1A43633A8723CD6FCE10519B40463CA67A6773C6566FE5A0F8F4089671D03B6AFBD0B42` |
| SSDEEP | `49152:znAQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvxJM0H9PAMEc:TDqPoBhz1aRxcSUDk36SAEdhvxWa9P5` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_029_1e4b319e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e4b319e9aaa514af9a0ca9b31bae004b8d5a77e9a6aa5edcd957025872710ba"
    family = "WannaCry"
    file_name = "mbupload-vq31wrg6.bin"
    file_type = "dll"
    first_seen = "2026-10-01 04:41:23"
  condition:
    hash.sha256(0, filesize) == "1e4b319e9aaa514af9a0ca9b31bae004b8d5a77e9a6aa5edcd957025872710ba"
}
```

### Sample 30: `035a6840a15e6dce`

| Field | Value |
|---|---|
| SHA-256 | `035a6840a15e6dcea0403627bb22f749e3aba785da74c839400d5209cccd5292` |
| Family label | `DDoSAgent` |
| File name | `mbupload-7381a5bi.bin` |
| File type | `elf` |
| First seen | `2026-10-01 04:41:16` |
| Reporter | `wristhulk` |
| Tags | `ddos, DDoSAgent, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bdfed27cf44b1f5825c81d9376a0959` |
| SHA-1 | `c4f06e4ad15588902ee9052c95895be4d7c2fae8` |
| SHA-256 | `035a6840a15e6dcea0403627bb22f749e3aba785da74c839400d5209cccd5292` |
| SHA3-384 | `bb54186d1408b08e293469124b0ee29f6172de01446711acd0e8cd65640414b209328d87f1d6614ef898e24fcd409250` |
| TLSH | `T191968D03EC9525E9C1EAA23189769252BB71BC491B3163D72B90F7386F73BC46E79340` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:+qlgEN3O8m7qSJu/6nvQAwJNE9y7FLVRXz7RmB7eQ9L5U+V7f3:+q+EtO88qSO6vfmFZRXP8rU+Vb` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_030_035a6840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "035a6840a15e6dcea0403627bb22f749e3aba785da74c839400d5209cccd5292"
    family = "DDoSAgent"
    file_name = "mbupload-7381a5bi.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:41:16"
  condition:
    hash.sha256(0, filesize) == "035a6840a15e6dcea0403627bb22f749e3aba785da74c839400d5209cccd5292"
}
```

### Sample 31: `6b844ca37d2f209a`

| Field | Value |
|---|---|
| SHA-256 | `6b844ca37d2f209a0136c4c337bdaeba4afc6c454b44dc351c248ceaae7fc135` |
| Family label | `DDoSAgent` |
| File name | `mbupload-zk08aeq1.bin` |
| File type | `elf` |
| First seen | `2026-10-01 04:41:07` |
| Reporter | `wristhulk` |
| Tags | `ddos, DDoSAgent, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a482141d3748a0c2c43a606787d01445` |
| SHA-1 | `fee7ffaea9f3774b941aa6ef489373e66e08a6cd` |
| SHA-256 | `6b844ca37d2f209a0136c4c337bdaeba4afc6c454b44dc351c248ceaae7fc135` |
| SHA3-384 | `8c7ee638aba788cc24a9b8ee34c0af5f013bd9239e0a310a491bbbe30dca085a48773d2b9e8c7168337e44dc37e10277` |
| TLSH | `T175C55C51FDCB44B6E9471E3248AF62AF23319D064F34EBC7E944BA29FA375D50932218` |
| TELFHASH | `t1244372409cf20ea76ac61777acf805c1236fd00f0655b3a95f64d37825eb08e653bb6a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:807TBrLDPQ+82Bz+FetWwAzOvVf5YT04Mq:h7TlY2B0nwYaf5Yg4X` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_031_6b844ca3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b844ca37d2f209a0136c4c337bdaeba4afc6c454b44dc351c248ceaae7fc135"
    family = "DDoSAgent"
    file_name = "mbupload-zk08aeq1.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:41:07"
  condition:
    hash.sha256(0, filesize) == "6b844ca37d2f209a0136c4c337bdaeba4afc6c454b44dc351c248ceaae7fc135"
}
```

### Sample 32: `ca13d65a37a6a747`

| Field | Value |
|---|---|
| SHA-256 | `ca13d65a37a6a7475a57fa4edb457f4059ba3cea9056d8a0c29bfa7db48ed108` |
| Family label | `SnakeBiteAgent` |
| File name | `Supply List_Purchase Order.zip` |
| File type | `zip` |
| First seen | `2026-10-01 04:41:05` |
| Reporter | `ppt_lol` |
| Tags | `SnakeBiteAgent, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d25b13ef5c15e4620a4e0a3008634e3b` |
| SHA-1 | `86f992b81df9e3d8249909f9517c48761bdec7c1` |
| SHA-256 | `ca13d65a37a6a7475a57fa4edb457f4059ba3cea9056d8a0c29bfa7db48ed108` |
| SHA3-384 | `ef075b7ffa9ea241bff95e09d43f254690edb022f308b86fc592d4583237171c62114aa6ad96c3a9bc0963e0b8021cb1` |
| TLSH | `T1EBF423D922F30F049EB42920D3B588FD7B9A4D0340459A8C2BFDE86F1E07DE6675CA59` |
| SSDEEP | `12288:v1qjbz0wlKpaef8UNsOGRaCE0TzU5CLaL5nWX8qJPEacrR7a0wKB8jjjeXX1LaeU:v1qjbz05aefvNsOGRaxaaLsjJParVpwJ` |

#### Technical Assessment

- The sample is tracked as `SnakeBiteAgent` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnakeBiteAgent_032_ca13d65a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca13d65a37a6a7475a57fa4edb457f4059ba3cea9056d8a0c29bfa7db48ed108"
    family = "SnakeBiteAgent"
    file_name = "Supply List_Purchase Order.zip"
    file_type = "zip"
    first_seen = "2026-10-01 04:41:05"
  condition:
    hash.sha256(0, filesize) == "ca13d65a37a6a7475a57fa4edb457f4059ba3cea9056d8a0c29bfa7db48ed108"
}
```

### Sample 33: `40bce4fc2d48b01e`

| Field | Value |
|---|---|
| SHA-256 | `40bce4fc2d48b01e29c714cd2478fb34d94688ba123a24ab69976599110939be` |
| Family label | `Mirai` |
| File name | `mbupload-4w4u3h99.bin` |
| File type | `elf` |
| First seen | `2026-10-01 04:40:59` |
| Reporter | `wristhulk` |
| Tags | `elf, honeypot, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5414d58b18082a7f1b8ef6924f731ac` |
| SHA-1 | `bde99547155468006524424078385dfd84b7d525` |
| SHA-256 | `40bce4fc2d48b01e29c714cd2478fb34d94688ba123a24ab69976599110939be` |
| SHA3-384 | `60ebf14671983c841d86b9f21059fe40d480cab3a58272201532f74098c74b83568352254f77ef0429189e13eac048a4` |
| TLSH | `T1393327C1B583F9F5EC11457C307BE7765E37F03AA03AEA9BD7959833A841A02D20629D` |
| TELFHASH | `t12a11e5b71e7a0df9f7e5a848c72e23920a59e637657073d05273d8206191dc1e0fac79` |
| SSDEEP | `1536:1M9zO39ul8ah+d++yqDPoPPOdTYGBfmaIzKHsab:wO3I+aod++ykoP2TgaoKHHb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_40bce4fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40bce4fc2d48b01e29c714cd2478fb34d94688ba123a24ab69976599110939be"
    family = "Mirai"
    file_name = "mbupload-4w4u3h99.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:40:59"
  condition:
    hash.sha256(0, filesize) == "40bce4fc2d48b01e29c714cd2478fb34d94688ba123a24ab69976599110939be"
}
```

### Sample 34: `3637ebd9a53af109`

| Field | Value |
|---|---|
| SHA-256 | `3637ebd9a53af109fd1ce055f074563d9749d099fb49e622023d5d01e3641168` |
| Family label | `Mirai` |
| File name | `mbupload-nzlbtikh.bin` |
| File type | `elf` |
| First seen | `2026-10-01 04:40:53` |
| Reporter | `wristhulk` |
| Tags | `elf, gafgyt, honeypot, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3e6347508c7a1f73288009829742ed3` |
| SHA-1 | `c45939de2dc51b6898271d95a406a6f78b7ec1a3` |
| SHA-256 | `3637ebd9a53af109fd1ce055f074563d9749d099fb49e622023d5d01e3641168` |
| SHA3-384 | `b5c8bdfe185d7c90717b69cd1e338b3231cbc4f4ba189ab53978591ee0b7578f9ed6316c265be6a3edac90b768ccc0c6` |
| TLSH | `T19A355C5BB2A374BCC157C434839BDA62BD35B46502226E7FA5C4DB302E26D702729F72` |
| TELFHASH | `t117e19d754bf9747162d6db14b322f0f55a331c22b1ed39b06a226d99ef85f810c7382a` |
| SSDEEP | `24576:OiOGv2Gcrj46X8xvGOoh2jTNUT1K09PsHOjgl3+8:OfFj46XLhkT2K0lsHOslu8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_3637ebd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3637ebd9a53af109fd1ce055f074563d9749d099fb49e622023d5d01e3641168"
    family = "Mirai"
    file_name = "mbupload-nzlbtikh.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:40:53"
  condition:
    hash.sha256(0, filesize) == "3637ebd9a53af109fd1ce055f074563d9749d099fb49e622023d5d01e3641168"
}
```

### Sample 35: `b94bb5e3dc898727`

| Field | Value |
|---|---|
| SHA-256 | `b94bb5e3dc898727f3e411fe174438450ccece7a4f801a5e0eb76a15c7db914c` |
| Family label | `Mirai` |
| File name | `mbupload-d1n6by16.bin` |
| File type | `elf` |
| First seen | `2026-10-01 04:40:45` |
| Reporter | `wristhulk` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0fc4a3d3f87a121b678669fce6ea9de8` |
| SHA-1 | `8630275a6093fbbc2805466445e3792ad38f9269` |
| SHA-256 | `b94bb5e3dc898727f3e411fe174438450ccece7a4f801a5e0eb76a15c7db914c` |
| SHA3-384 | `6ef73a5d12380e15e08fb4548f3bfb239ecc456b83fe6f6659ab26696495fcc58d7b828e99fc6faeefafa19a46985ed4` |
| TLSH | `T143355C5BB2A374BCC157C434839BDA62BD35B46502226E7FA5C4DB302E26D702729F72` |
| TELFHASH | `t117e19d754bf9747162d6db14b322f0f55a331c22b1ed39b06a226d99ef85f810c7382a` |
| SSDEEP | `24576:OiOGv2Gcrj46X8xvGOoh2jTNUT1K09PsHOjgl3+r:OfFj46XLhkT2K0lsHOslur` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_b94bb5e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94bb5e3dc898727f3e411fe174438450ccece7a4f801a5e0eb76a15c7db914c"
    family = "Mirai"
    file_name = "mbupload-d1n6by16.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:40:45"
  condition:
    hash.sha256(0, filesize) == "b94bb5e3dc898727f3e411fe174438450ccece7a4f801a5e0eb76a15c7db914c"
}
```

### Sample 36: `4610ccf1547c2cb4`

| Field | Value |
|---|---|
| SHA-256 | `4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f` |
| Family label | `unknown` |
| File name | `4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f.bin` |
| File type | `zip` |
| First seen | `2026-10-01 04:28:49` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e50c1397356981d98f1cf1b79cf59b1e` |
| SHA-1 | `8384bcde8e600a86a7cccbf0a722f0ab9b498945` |
| SHA-256 | `4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f` |
| SHA3-384 | `ad47180ea71b8cba0bca7f3e22fc2e19199dfa2665448e7baeafb504507e89694c337af5af9098ffb4832923dd243339` |
| TLSH | `T152753303AA7CA413FCB38274875DA3EACAC570564D84CA7B5E7582218D9BFD40E3C57A` |
| SSDEEP | `49152:WOCgIc2WxI0tHwTTbF0kOSY/LdGgrF35Wwd:WQIci0tHwTTbF0kdYxGAv3d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_4610ccf1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f"
    family = "unknown"
    file_name = "4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f.bin"
    file_type = "zip"
    first_seen = "2026-10-01 04:28:49"
  condition:
    hash.sha256(0, filesize) == "4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f"
}
```

### Sample 37: `11b606a4c098c99a`

| Field | Value |
|---|---|
| SHA-256 | `11b606a4c098c99a6fae1c6c56fa09590616fe503639308b5e773c83df85b94e` |
| Family label | `Mirai` |
| File name | `fa6f34f439e2f40f.bin` |
| File type | `elf` |
| First seen | `2026-10-01 04:25:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5abbca534f527fd9c75a0905c7bb922e` |
| SHA-1 | `59e4e71826c0e36e653d044da368c4508fe109b3` |
| SHA-256 | `11b606a4c098c99a6fae1c6c56fa09590616fe503639308b5e773c83df85b94e` |
| SHA3-384 | `62458bb30cf33cf901838ee75beab4c3f74656c8b1f00b6aa0666e63f0756523988880d2b049ada4d574529900c0bc60` |
| TLSH | `T186B44C89BC809B65D5D11BBBFF2E924833131BB8E2EF71074D145B645B8BC9A0F7A601` |
| TELFHASH | `t18a61aa916edd11bcb2e69680c1fea1259569318e4f402d634d24ba2e5d036c1712ec23` |
| SSDEEP | `12288:d7MnucQH6VwnqVA725cfy9Ybxu38tyDGuQfMV27PXHJcuLvgT5oK7vz7KrnTv7V4:ZGISU7/JcuW5WrFM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_11b606a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11b606a4c098c99a6fae1c6c56fa09590616fe503639308b5e773c83df85b94e"
    family = "Mirai"
    file_name = "fa6f34f439e2f40f.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:25:24"
  condition:
    hash.sha256(0, filesize) == "11b606a4c098c99a6fae1c6c56fa09590616fe503639308b5e773c83df85b94e"
}
```

### Sample 38: `fa6f34f439e2f40f`

| Field | Value |
|---|---|
| SHA-256 | `fa6f34f439e2f40fcdccaa83a88e08fbe2e9285eba8c9e29228df3e3c16c1078` |
| Family label | `Mirai` |
| File name | `fa6f34f439e2f40f.bin` |
| File type | `elf` |
| First seen | `2026-10-01 04:24:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dc7c3777d28b4cc65edc88419fcd98a` |
| SHA-1 | `746476aa5066f571e58598f0d977fca8f0831e6c` |
| SHA-256 | `fa6f34f439e2f40fcdccaa83a88e08fbe2e9285eba8c9e29228df3e3c16c1078` |
| SHA3-384 | `aacbdf0edef6b95e8c117c0b1d9dc5f0b2a557155fa78fd42944b43f0c983712cdd6431540b50541ee3632f1ac89ed64` |
| TLSH | `T1633423F5C610CDA4AE7F453C0690A7326702A1646B9EEEE236B1355F8CE85EC7356E03` |
| SSDEEP | `3072:oLVnem5HE0R6fa96XlauUvyvblgRT+d6Drpr3LPz/rpK7y9d9rEQhDRxTL2ARe5/:kjHbvClMvCbuIdERLPz/rdxnJL2+Suu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_fa6f34f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa6f34f439e2f40fcdccaa83a88e08fbe2e9285eba8c9e29228df3e3c16c1078"
    family = "Mirai"
    file_name = "fa6f34f439e2f40f.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:24:44"
  condition:
    hash.sha256(0, filesize) == "fa6f34f439e2f40fcdccaa83a88e08fbe2e9285eba8c9e29228df3e3c16c1078"
}
```

### Sample 39: `1beabccc2954acee`

| Field | Value |
|---|---|
| SHA-256 | `1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e` |
| Family label | `unknown` |
| File name | `1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e.exe` |
| File type | `exe` |
| First seen | `2026-10-01 04:18:37` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba5c90e12f6331a0337f864b6c9fa979` |
| SHA-1 | `0e42bf124555ce4fede49df38df2a447339584fd` |
| SHA-256 | `1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e` |
| SHA3-384 | `bfa639f36cd55feaf73bc105944aa52952af666b7ef31c3139e5a07e573fdfc8b13d1b5fb498c9bd42a1ea9bcaac744f` |
| IMPHASH | `b73463e2c02bcc27c18c5f758c7fc511` |
| TLSH | `T13AB54A21F692CA72C473113248B64B750A34FEE05F9056D76398345B3E767E0BE26BE8` |
| SSDEEP | `49152:50mbtroVy1ysy5IGWnFO+BiNHCFojMLByWsYN:50mJok1Ny5EFojY` |
| ICON-DHASH | `0733496969493317` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_1beabccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e"
    family = "unknown"
    file_name = "1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:18:37"
  condition:
    hash.sha256(0, filesize) == "1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e"
}
```

### Sample 40: `db11b9baed28a208`

| Field | Value |
|---|---|
| SHA-256 | `db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6` |
| Family label | `Mirai` |
| File name | `db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6` |
| File type | `elf` |
| First seen | `2026-10-01 04:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `246c5beb63fae22af17451fdd49e0168` |
| SHA-1 | `01e8c03a327c33071b5024e60bbaef811b892da5` |
| SHA-256 | `db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6` |
| SHA3-384 | `97f403948fdb429cd2e2d1b45a49bafbd239eb9469bec394ec0e1b70d6f197880103ff837de75ba9aaa896a5e953627c` |
| TLSH | `T1A644398AFD80AF25D5C5267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ5:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_db11b9ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6"
    family = "Mirai"
    file_name = "db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6"
    file_type = "elf"
    first_seen = "2026-10-01 04:17:14"
  condition:
    hash.sha256(0, filesize) == "db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6"
}
```

### Sample 41: `1e3bc11e2a840461`

| Field | Value |
|---|---|
| SHA-256 | `1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666` |
| Family label | `CoinMiner` |
| File name | `1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666.exe` |
| File type | `exe` |
| First seen | `2026-10-01 04:13:37` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af46fb43b1de58466bd6d99d56a022fd` |
| SHA-1 | `4b75da1a09141ccb89f06fdd99a0a282cc2b79ef` |
| SHA-256 | `1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666` |
| SHA3-384 | `e4ab862cc0c90bc06ac7c71c6b05913accb77579c85d6c4274a82bc19753d2107ae0952069b95c6c16aa5089a93d3e4b` |
| IMPHASH | `26b5ef95ca1087031e1773e20c482ce9` |
| TLSH | `T155357C83E7A381D8C166D8B5534BF137F9627C8E4A157196ABC41E633E77B64E22CB00` |
| SSDEEP | `12288:sVgGe4U/H/6S5Wu9sdc90EBBBHGBdSKikwLQvgqItNq:sVgGexv/6K6dEHkwMvg3f` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_041_1e3bc11e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666"
    family = "CoinMiner"
    file_name = "1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:13:37"
  condition:
    hash.sha256(0, filesize) == "1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666"
}
```

### Sample 42: `5adc928c90571c9c`

| Field | Value |
|---|---|
| SHA-256 | `5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8` |
| Family label | `ConnectWise` |
| File name | `5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8.exe` |
| File type | `exe` |
| First seen | `2026-10-01 04:13:15` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0366ba53452891f711bc11b8c3e0186` |
| SHA-1 | `51e89f10827bcc2159a2555f2cb7d9f4644d1a52` |
| SHA-256 | `5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8` |
| SHA3-384 | `211edcec1476c443eb1f7bdb129face480faedd470892882b3b02ee721100b4f5bf0b49391ee8629642938bdeccc9edd` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1F446F141B3D695B5D4BF0678D87A52AA5A34BC048312C7FF57A4BD293D327C08E323A6` |
| SSDEEP | `98304:Eds6efPc66x9G6GYjTG7WSvhrG9N9vlcU:yfefPQHGYjMi9N9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_042_5adc928c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8"
    family = "ConnectWise"
    file_name = "5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:13:15"
  condition:
    hash.sha256(0, filesize) == "5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8"
}
```

### Sample 43: `145e01a971611cdb`

| Field | Value |
|---|---|
| SHA-256 | `145e01a971611cdb401e8122899478a3c071f308e695726306baedf191b9fd7e` |
| Family label | `unknown` |
| File name | `reg.exe` |
| File type | `exe` |
| First seen | `2026-10-01 04:11:56` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c222649c339536928bb1c59ad239eaf3` |
| SHA-256 | `145e01a971611cdb401e8122899478a3c071f308e695726306baedf191b9fd7e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_145e01a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "145e01a971611cdb401e8122899478a3c071f308e695726306baedf191b9fd7e"
    family = "unknown"
    file_name = "reg.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:11:56"
  condition:
    hash.sha256(0, filesize) == "145e01a971611cdb401e8122899478a3c071f308e695726306baedf191b9fd7e"
}
```

### Sample 44: `786169a79bb50577`

| Field | Value |
|---|---|
| SHA-256 | `786169a79bb505773566b041070dee3bb1c6ea67385acfc63ecf989ce701c87a` |
| Family label | `Formbook` |
| File name | `mv TOI CHALLENGER SHIP INFORMATION.com` |
| File type | `exe` |
| First seen | `2026-10-01 04:06:20` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dffdcc1f6a5cf3e7dfe90493cacf741` |
| SHA-1 | `b6c1e9f485ef7a3a2caea2f4f94f7b6db1af6d8a` |
| SHA-256 | `786169a79bb505773566b041070dee3bb1c6ea67385acfc63ecf989ce701c87a` |
| SHA3-384 | `77925580258dd7921835cec8bff89c8eb4abe211636dbc21bc0fe951f1907d37ba3acbc7584d9c9b1e3729c31bf2e039` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14E05F1187A5FEC03C1B9033189E1E27403B59E8DE512D35B9FEA5DD73922B8668D8783` |
| SSDEEP | `12288:FMAdszX5xvbrPIV9dYnOTNDnyl1zCILrnGBcQjVwxqYoW6Cm7dmhFBgWZ7NDU:o3PWTNDnylgILrGHKo/CmYh1DU` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_044_786169a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "786169a79bb505773566b041070dee3bb1c6ea67385acfc63ecf989ce701c87a"
    family = "Formbook"
    file_name = "mv TOI CHALLENGER SHIP INFORMATION.com"
    file_type = "exe"
    first_seen = "2026-10-01 04:06:20"
  condition:
    hash.sha256(0, filesize) == "786169a79bb505773566b041070dee3bb1c6ea67385acfc63ecf989ce701c87a"
}
```

### Sample 45: `e76c5c79066d31f5`

| Field | Value |
|---|---|
| SHA-256 | `e76c5c79066d31f5e84b172d61ba575926a18505efa47a9d9a0c7c1c0ced4768` |
| Family label | `AgentTesla` |
| File name | `Shipment_Invoice_and_Packing_List.com` |
| File type | `exe` |
| First seen | `2026-10-01 04:03:48` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a7527626bfbc9702ad9fe8428889361` |
| SHA-1 | `6eddd24221c19404b63350c2aee80bf919577d69` |
| SHA-256 | `e76c5c79066d31f5e84b172d61ba575926a18505efa47a9d9a0c7c1c0ced4768` |
| SHA3-384 | `258ae54b8c8e6660ddd7f5af6758bdf8abf743f3b9d99dc478403eb6ba967cafeb84d4b8bd37c02d984fbf26b9144ece` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1AEF4F1286A5FDD13C47A077148E0F67413B15E8DE522D38B8EEE6DE73A21BC55CD8282` |
| SSDEEP | `12288:ncObdlm/X5xiMbSNk5Wpvnbzf4hu6yoRH+EkEMzEqBlvZO1XTHwZv/vztBYto2DN:cOOSR1n/4hDLHoEfcONcxb06` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_045_e76c5c79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76c5c79066d31f5e84b172d61ba575926a18505efa47a9d9a0c7c1c0ced4768"
    family = "AgentTesla"
    file_name = "Shipment_Invoice_and_Packing_List.com"
    file_type = "exe"
    first_seen = "2026-10-01 04:03:48"
  condition:
    hash.sha256(0, filesize) == "e76c5c79066d31f5e84b172d61ba575926a18505efa47a9d9a0c7c1c0ced4768"
}
```

### Sample 46: `84d68a89a5f07f09`

| Field | Value |
|---|---|
| SHA-256 | `84d68a89a5f07f096cca74e9c96869490056e8b911fd84cd73e5744bed1a7022` |
| Family label | `unknown` |
| File name | `InitialPayload.jar` |
| File type | `jar` |
| First seen | `2026-10-01 03:58:16` |
| Reporter | `hexinglarps` |
| Tags | `jar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d3de995c74da86c6e427b2eb555d5c5` |
| SHA-1 | `4703fdce9ad9e1199ccc42c64cadeb0a2d1717a8` |
| SHA-256 | `84d68a89a5f07f096cca74e9c96869490056e8b911fd84cd73e5744bed1a7022` |
| SHA3-384 | `97a2211db296fdbf8034755bb8073fcf819bdf49f9c4d14c12a8c85a7c533e2cfcd58999f4617d04eea5a9f925d4732c` |
| TLSH | `T1C8753303592CE813FCE382748B8EB3EAC9C5705A4D859A7F4E7552218D5FFD40E2C9A6` |
| SSDEEP | `49152:J5m6sUcfSAV3WLXl/0EAOuJvdUOzJ3dWfb:66seAV3WLXl/0EDuTUyjob` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_84d68a89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d68a89a5f07f096cca74e9c96869490056e8b911fd84cd73e5744bed1a7022"
    family = "unknown"
    file_name = "InitialPayload.jar"
    file_type = "jar"
    first_seen = "2026-10-01 03:58:16"
  condition:
    hash.sha256(0, filesize) == "84d68a89a5f07f096cca74e9c96869490056e8b911fd84cd73e5744bed1a7022"
}
```

### Sample 47: `7b254af99efa15b1`

| Field | Value |
|---|---|
| SHA-256 | `7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1` |
| Family label | `GCleaner` |
| File name | `7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1.exe` |
| File type | `exe` |
| First seen | `2026-10-01 03:42:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, GCleaner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c08f622f58f7afd2dc94a5c6822bb172` |
| SHA-1 | `07c1a6c1f14bec44a73dd614815da7032b9ea77f` |
| SHA-256 | `7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1` |
| SHA3-384 | `5ef2aad5ee149a93620486e9b9c0181dfa60b26674259c1b39ae558a57c8241b034d3260840bc7d68d5bdfb88d955e88` |
| IMPHASH | `06426283b2b3079382b630b914de88af` |
| TLSH | `T110159E22A2B1C437C1B23BFF8D2B52B598AAFE013D3854496FE54D4C0E3B65179253A7` |
| SSDEEP | `24576:R1EmyAyseR6UqDBwcm0zGLANwwL2u9I1Dc:R1/y/skKSuKS` |
| ICON-DHASH | `399998ecd4d46c0e` |

#### Technical Assessment

- The sample is tracked as `GCleaner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GCleaner_047_7b254af9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1"
    family = "GCleaner"
    file_name = "7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:42:49"
  condition:
    hash.sha256(0, filesize) == "7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1"
}
```

### Sample 48: `87568fa4215f1e23`

| Field | Value |
|---|---|
| SHA-256 | `87568fa4215f1e230bf15f9bdb88528b7ad5d58e9ffb51324dc37c6ecfa00e99` |
| Family label | `Mirai` |
| File name | `mbupload-152sjsqs.bin` |
| File type | `elf` |
| First seen | `2026-10-01 03:39:49` |
| Reporter | `wristhulk` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f699d0fc7fcc0f8c512f800d9c0b488` |
| SHA-1 | `2c3f1fb29c7333754829a5c8cc7eeb362ced7c61` |
| SHA-256 | `87568fa4215f1e230bf15f9bdb88528b7ad5d58e9ffb51324dc37c6ecfa00e99` |
| SHA3-384 | `331ddd39cc0d76cc4e9c284b77af27c789c09972527b9f79e27986726e9680acf6347337b084de4b9fbc17bda59df3da` |
| TLSH | `T12073731AA662CA79C042E2341FEFD290A521B4F46F36610B375567773F71B888B29F13` |
| TELFHASH | `t1a3f08142693d8a5486f35670cc111b93a28397724432ee28ef58e6c0943f159f238e9b` |
| SSDEEP | `1536:PUQvTY0Ti/h59EFX3c7iQjytiY0G59pn0Hr70FXqH3aicCGwvh2nKGF:PTY0Tij9l9aP0HrwFXqHXcCxYV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_87568fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87568fa4215f1e230bf15f9bdb88528b7ad5d58e9ffb51324dc37c6ecfa00e99"
    family = "Mirai"
    file_name = "mbupload-152sjsqs.bin"
    file_type = "elf"
    first_seen = "2026-10-01 03:39:49"
  condition:
    hash.sha256(0, filesize) == "87568fa4215f1e230bf15f9bdb88528b7ad5d58e9ffb51324dc37c6ecfa00e99"
}
```

### Sample 49: `5fef2449ce26f082`

| Field | Value |
|---|---|
| SHA-256 | `5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81` |
| Family label | `unknown` |
| File name | `5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81.bin` |
| File type | `apk` |
| First seen | `2026-10-01 03:32:47` |
| Reporter | `Tuxxin` |
| Tags | `apk, signed, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de72ddf5a58637df2c98e12f752b9508` |
| SHA-1 | `122f50ea6a45cd4dffe87204a31701e87d42c315` |
| SHA-256 | `5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81` |
| SHA3-384 | `8d017412af1365a2ebabae93539989086ff648e329206d2607bfe0f971d8c9888d0f90e0af3467b24bdea0dceadf9ed3` |
| TLSH | `T1941733BC2E79F638DA69B67C85F300275C59426C32DAFE3D8779476848E5D80372898C` |
| SSDEEP | `393216:LZKfViLWILindO91f1EI4mG6PnOoBt3RTh4ZKfZFqKRSSOb4bUud6LU9lgyFKaaC:LkfViLnmndIfEI4OPnO2Vh4kfyKR1Os7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_5fef2449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81"
    family = "unknown"
    file_name = "5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81.bin"
    file_type = "apk"
    first_seen = "2026-10-01 03:32:47"
  condition:
    hash.sha256(0, filesize) == "5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81"
}
```

### Sample 50: `2a6f2f273af0d9b0`

| Field | Value |
|---|---|
| SHA-256 | `2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4` |
| Family label | `unknown` |
| File name | `2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4.bin` |
| File type | `apk` |
| First seen | `2026-10-01 03:28:44` |
| Reporter | `Tuxxin` |
| Tags | `apk, signed, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c364c4007e341e9e4c37cb925089dbf5` |
| SHA-1 | `3fad1ba3ef588ca05eecadce19553ed9ce953fc5` |
| SHA-256 | `2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4` |
| SHA3-384 | `f4ba56e5b6728dc589d09e92cf61f0fc1f3faa31a6e143b93b80b13245ad1a25e807b3a4989bfbca1915b85e8f663dfd` |
| TLSH | `T14E56F0CAFBC899AAC4F75332D53656A245474C268B83DEC75954353C28BB6D00F8EBC8` |
| SSDEEP | `196608:dgBqRpvW9Bil/9jv8QZ/fBPcR2ZGaPjWSnHfLSzm9PDw:TpeHOpS4bPHH8m90` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_2a6f2f27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4"
    family = "unknown"
    file_name = "2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4.bin"
    file_type = "apk"
    first_seen = "2026-10-01 03:28:44"
  condition:
    hash.sha256(0, filesize) == "2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4"
}
```

### Sample 51: `b25ead9ba12a34db`

| Field | Value |
|---|---|
| SHA-256 | `b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21` |
| Family label | `VShell` |
| File name | `b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21.exe` |
| File type | `exe` |
| First seen | `2026-10-01 03:28:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cd1fa89c6b1a2f54a46385bfd14c198` |
| SHA-1 | `7cd8d503afce1153df72b23c0bd4e6b1c2397152` |
| SHA-256 | `b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21` |
| SHA3-384 | `b1fc3c30a9dd943caecddf9b095f6fbb1505c6d23878541ab83f0b05e8bf2f5b58aae4c46323f69c34a1aa6e15e7f6b8` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1BA716198F3175AF1E43C47F840D3A524C019ABBCC250BF4D5E60381D3C210BA255AF97` |
| SSDEEP | `48:6Icwm00t2WSJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jhtQSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_051_b25ead9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21"
    family = "VShell"
    file_name = "b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:28:35"
  condition:
    hash.sha256(0, filesize) == "b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21"
}
```

### Sample 52: `635f0f9aed2508d4`

| Field | Value |
|---|---|
| SHA-256 | `635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e` |
| Family label | `VShell` |
| File name | `635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e.exe` |
| File type | `exe` |
| First seen | `2026-10-01 03:27:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e707b4630e8a0deb0d4381e2646b7802` |
| SHA-1 | `e3e775ef528521fd047913fe33e2916f6e93d066` |
| SHA-256 | `635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e` |
| SHA3-384 | `a22eb842989ba9bae83e8f49f0bcfc91834c7ae756feaf61442fb921a817db3ca8084bb85b229bc0ea559bc082db46fd` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1A591A5C5F757E6B2EC1C17F500A379A4C4A82E18827C9B564FE16F0C7C111AA3D3DA52` |
| SSDEEP | `48:6I7lwe7v7r08SlJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1709Xq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_052_635f0f9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e"
    family = "VShell"
    file_name = "635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:27:47"
  condition:
    hash.sha256(0, filesize) == "635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e"
}
```

### Sample 53: `629d2985c6173cb4`

| Field | Value |
|---|---|
| SHA-256 | `629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1` |
| Family label | `unknown` |
| File name | `629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1.bin` |
| File type | `zip` |
| First seen | `2026-10-01 03:18:28` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a330f42706624698c305d0709d269b0` |
| SHA-1 | `96f8823997cae33c57867e1e6f5a54fcab1771c7` |
| SHA-256 | `629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1` |
| SHA3-384 | `d15b5e9691dbb99953e8d1fcc484d90f8074cd484f609ed82d901be20c93a24e2daf180e8637757c6bf03c510182496d` |
| TLSH | `T1D4A4231AEA92A98CF319053ED2C014F9D5C7D4A9350F8A1473D4D1BAECFC850366AEED` |
| SSDEEP | `12288:hmSDq6jCuEKbP9mh73Zg+3G8e29Cdsw07hGE:nDxjTwriL8e2cawe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_629d2985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1"
    family = "unknown"
    file_name = "629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1.bin"
    file_type = "zip"
    first_seen = "2026-10-01 03:18:28"
  condition:
    hash.sha256(0, filesize) == "629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1"
}
```

### Sample 54: `63c9b46cfaa62abf`

| Field | Value |
|---|---|
| SHA-256 | `63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221` |
| Family label | `unknown` |
| File name | `63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221.bin` |
| File type | `zip` |
| First seen | `2026-10-01 03:17:47` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e40d26a2acdfa7bfe503785935c5bde9` |
| SHA-1 | `9953ab1fa103a5b2d6598d334fb3c6ac2e8f0e05` |
| SHA-256 | `63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221` |
| SHA3-384 | `b544beff0d6ef395952b66a8f646384a5dd85deb786ba647b08feb5ce00302cd3218c82c3869d649994455966b1ab6bb` |
| TLSH | `T19B5423FD1360907C955FDAE542967C2C9EC8786A6D9804382F3A9CA43122E9912CFC7F` |
| SSDEEP | `6144:42fiYvAVeAunZntnLYxtzPYihwMiZH/YhpNriNRWIU:hfisAwtZnVitfiB/Y/NiRa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_63c9b46c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221"
    family = "unknown"
    file_name = "63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221.bin"
    file_type = "zip"
    first_seen = "2026-10-01 03:17:47"
  condition:
    hash.sha256(0, filesize) == "63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221"
}
```

### Sample 55: `2f03d283a5302a74`

| Field | Value |
|---|---|
| SHA-256 | `2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65` |
| Family label | `Mirai` |
| File name | `2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65` |
| File type | `elf` |
| First seen | `2026-10-01 03:17:15` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67b3020d7924d609ff3991231e86d010` |
| SHA-1 | `3010cf7215da6d899235c3b7741ecae580385891` |
| SHA-256 | `2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65` |
| SHA3-384 | `56c9e0b8c4e2c523fcb59a384acc639df91a7a5e19915b867cfbeb3779bcebecb8e7eb1498c5f86be0a254cdeb52479d` |
| TLSH | `T123543A8AFD81AE25D5C1267BFE2F428A331317B8D2EB71129D145F2876CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJL:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_2f03d283
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65"
    family = "Mirai"
    file_name = "2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65"
    file_type = "elf"
    first_seen = "2026-10-01 03:17:15"
  condition:
    hash.sha256(0, filesize) == "2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65"
}
```

### Sample 56: `8570d8ec3fdb3449`

| Field | Value |
|---|---|
| SHA-256 | `8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0` |
| Family label | `unknown` |
| File name | `8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0.bin` |
| File type | `zip` |
| First seen | `2026-10-01 03:13:49` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3b002b88b03831729f2672459ae3e0e` |
| SHA-1 | `1aa75add71e1b9b33b76dafac944f29caa47abf7` |
| SHA-256 | `8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0` |
| SHA3-384 | `52d157d3c26109ba9bf25471f8d1649f24f703b2184592c86e449500830818576b18c7d0ef36454dd74171a62ca62120` |
| TLSH | `T1B91733F8479FDD7477C0EAF948052BC553BBAA1D3A606465CF02AAB358F04143768ACE` |
| SSDEEP | `393216:epQwaDqPD+cDnDYuWJb3hinmQrTIyv6HX4O223U7mLCsI:ephWxcDnDYuuQDrTf4W2ESLI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_8570d8ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0"
    family = "unknown"
    file_name = "8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0.bin"
    file_type = "zip"
    first_seen = "2026-10-01 03:13:49"
  condition:
    hash.sha256(0, filesize) == "8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0"
}
```

### Sample 57: `e598af514da17a32`

| Field | Value |
|---|---|
| SHA-256 | `e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e` |
| Family label | `unknown` |
| File name | `e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e.exe` |
| File type | `exe` |
| First seen | `2026-10-01 03:12:54` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0265798a69f9bd74f6bce239aee45676` |
| SHA-1 | `20ccee4e82147431e714a1a425b73ca82c3e36e7` |
| SHA-256 | `e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e` |
| SHA3-384 | `d45c248b4725c38260af542c8a4fd0ff17b674e7aea51a2603a2b34cec8450779848fec88da0b06c0cb2086dba3d570a` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T1C5B67B03EC5558E9C1ADD2318AB691537B71BC490B3223D71B90B7386E73BE0AEB9345` |
| SSDEEP | `196608:qr0nQ7oprII+KqGdz3LJkneNEVZcHaIO:zQ0prt+LGPkDV0O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_e598af51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e"
    family = "unknown"
    file_name = "e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:12:54"
  condition:
    hash.sha256(0, filesize) == "e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e"
}
```

### Sample 58: `279059e4ec630097`

| Field | Value |
|---|---|
| SHA-256 | `279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f` |
| Family label | `DattoRMM` |
| File name | `279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f.exe` |
| File type | `exe` |
| First seen | `2026-10-01 02:58:22` |
| Reporter | `Tuxxin` |
| Tags | `DattoRMM, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3b53581b340647f342144c44c611967` |
| SHA-1 | `e4fb10a7e74dc8d4b81e29aaec5993a8714bd5a4` |
| SHA-256 | `279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f` |
| SHA3-384 | `e5e27c0f305ed15cfcb995657a34c469feee4586f6c845030a5d9d3db26ddda465e1e5eb44993edac7ae1d053e045860` |
| IMPHASH | `187b3ae62ff818788b8c779ef7bc3d1c` |
| TLSH | `T17AB63313D57BCCE1CB234678D6E10A46BB4A018A9C5AB8D4F584633E55D34ADEF38B8C` |
| SSDEEP | `196608:4aZk+wA0rsRTjTtR43PG8PZHj2BPFOsti7A95R8jsFp29XaIT030Hy05s6r8Ar8p:SnA04RT9R4PkE7Ap84p29qIT0Z6rXr8p` |
| ICON-DHASH | `f0ccce71b6b6dcf0` |

#### Technical Assessment

- The sample is tracked as `DattoRMM` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DattoRMM_058_279059e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f"
    family = "DattoRMM"
    file_name = "279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:58:22"
  condition:
    hash.sha256(0, filesize) == "279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f"
}
```

### Sample 59: `9350cc4d7e1b7fd8`

| Field | Value |
|---|---|
| SHA-256 | `9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343` |
| Family label | `Mirai` |
| File name | `9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343.elf` |
| File type | `elf` |
| First seen | `2026-10-01 02:57:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8503b66692505016cf1a42833aebd20f` |
| SHA-1 | `ba1ccbdeb27e0b5322912cd7a2ea6e61ff37052a` |
| SHA-256 | `9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343` |
| SHA3-384 | `bdf716bf1a3f08e565a8c5905911afefa91d5f139c4e4185dcd9ead2bd2906b8be8ee7b52b7ae75a9df8de2d9ea1d216` |
| TLSH | `T190C68C4BB5A714BCC19BC470835BD562B971385801753E7F3A84DA702E66E342BBEF22` |
| TELFHASH | `t11f12dbb149ea3ce1a6dac517f763f0b5a53328f61ae8397022376d41dfd1e800c6981b` |
| SSDEEP | `98304:8f8u5C67uk+I7r60cxNl1ds8AGy/EbYtMd1Uj5Ans9LcD9SZh1y6ibXmuYZB7e8z:E55Jjf7fmzVlr8ELJZ19b4m8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_9350cc4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343"
    family = "Mirai"
    file_name = "9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343.elf"
    file_type = "elf"
    first_seen = "2026-10-01 02:57:52"
  condition:
    hash.sha256(0, filesize) == "9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343"
}
```

### Sample 60: `116eeeceb2de4e54`

| Field | Value |
|---|---|
| SHA-256 | `116eeeceb2de4e549b94a81009755e745ced15b6189bc2ffa1574550307b8245` |
| Family label | `unknown` |
| File name | `4c7d6f187d17322c675cbaeb248c7dc5` |
| File type | `dll` |
| First seen | `2026-10-01 02:50:35` |
| Reporter | `AmStaff7021` |
| Tags | `dionaea, dll, exe, honeypot, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c7d6f187d17322c675cbaeb248c7dc5` |
| SHA-1 | `8c880f0bc445ed43cd1307a8cbcd59b1b413d27c` |
| SHA-256 | `116eeeceb2de4e549b94a81009755e745ced15b6189bc2ffa1574550307b8245` |
| SHA3-384 | `54438b51768ae196a84d84396f1105aeb7428141f761fdbc034171ebc35f57b01e0c64ce70aeae724f6660c813877e0a` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T17736F142D1D50EA0D5F10FF6226BDB10927F6E1596ABA12E6621901F1CB7F0C8DE6F2C` |
| SSDEEP | `98304:dDqPoBhz1aRxcSUDkA6SAEdhvxWa9C93R8yAVp2H:dDqPe1CxcxkAZAEUamR8yc4H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_116eeece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "116eeeceb2de4e549b94a81009755e745ced15b6189bc2ffa1574550307b8245"
    family = "unknown"
    file_name = "4c7d6f187d17322c675cbaeb248c7dc5"
    file_type = "dll"
    first_seen = "2026-10-01 02:50:35"
  condition:
    hash.sha256(0, filesize) == "116eeeceb2de4e549b94a81009755e745ced15b6189bc2ffa1574550307b8245"
}
```

### Sample 61: `07adbb53e9cfea58`

| Field | Value |
|---|---|
| SHA-256 | `07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9` |
| Family label | `Heodo` |
| File name | `07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9.msi` |
| File type | `msi` |
| First seen | `2026-10-01 02:47:58` |
| Reporter | `Tuxxin` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2664adae5f401de460ed527714e72aca` |
| SHA-1 | `26758d38c9bca73ca88c6934d299c67e96b6f029` |
| SHA-256 | `07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9` |
| SHA3-384 | `4caedcfa1236f48de0a3a46c2ba12a702ea9318e3e77e06cb32ab851ba450195b2d884844cd5836817f5d9a8772306e6` |
| TLSH | `T1B9873306FAAD4195DDA5E078C96B460FD3B1B820033096CF02755B8EEF7B7D2593A368` |
| SSDEEP | `786432:9RAf2rfJVK4/gXN9MXjvoMrQSBlDotpOjrWyDE:9RAfMfJ/tQSBl8AjnD` |

#### Technical Assessment

- The sample is tracked as `Heodo` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Heodo_061_07adbb53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9"
    family = "Heodo"
    file_name = "07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9.msi"
    file_type = "msi"
    first_seen = "2026-10-01 02:47:58"
  condition:
    hash.sha256(0, filesize) == "07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9"
}
```

### Sample 62: `53cc143c730ee92d`

| Field | Value |
|---|---|
| SHA-256 | `53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7` |
| Family label | `VShell` |
| File name | `53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7.exe` |
| File type | `exe` |
| First seen | `2026-10-01 02:47:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54f9c30fd7d545c85a0b1bef737b0e4d` |
| SHA-1 | `5a26b4a2c77077e9c194b9ff9e0e6f0193036349` |
| SHA-256 | `53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7` |
| SHA3-384 | `39c757bcb74944715bf16bd616d15dafe25253abca107a6a3e0817d263e8717e1d42aeb0f37ce394ae443b5b4832acb4` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E4715098F3176AF5E43C86F84093A624D519ABBCC250AE4D5A60281D3C610BA255AF96` |
| SSDEEP | `48:6Icwm02/Mt2WRhJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4j1Ut1HSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_062_53cc143c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7"
    family = "VShell"
    file_name = "53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:47:47"
  condition:
    hash.sha256(0, filesize) == "53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7"
}
```

### Sample 63: `b45e3b14e530db32`

| Field | Value |
|---|---|
| SHA-256 | `b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c` |
| Family label | `unknown` |
| File name | `b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c.exe` |
| File type | `exe` |
| First seen | `2026-10-01 02:39:20` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a11cda32d9271376f2ba2c1bfe55855e` |
| SHA-1 | `5bd0fe107df23f83454f7a74f3c2395c867988ab` |
| SHA-256 | `b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c` |
| SHA3-384 | `b15f6c233064d8de28602eb57fa582d682c3367d792946dbd5299893236291a8ac9b568acae4ec3d841e38160f71f0c4` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1AC823C09779ADE2AC5BF5A3836B3A01457B5A5116311FB9A1EDFB0FE1CA3F00410A6D3` |
| SSDEEP | `384:kqP+uGxFYcDBNqTagbhg+i6S2G60/+VXR14IzEXAOy4Vk4VkH:qPfcw6S23VUIrOSH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_b45e3b14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c"
    family = "unknown"
    file_name = "b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:39:20"
  condition:
    hash.sha256(0, filesize) == "b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c"
}
```

### Sample 64: `4e1d821d4df8a1bc`

| Field | Value |
|---|---|
| SHA-256 | `4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50` |
| Family label | `unknown` |
| File name | `4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50.exe` |
| File type | `exe` |
| First seen | `2026-10-01 02:38:37` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47ffceafe202f8a12372c08f284cdeed` |
| SHA-1 | `f7bbe5282cdae021194a48095eb5ab842a54825a` |
| SHA-256 | `4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50` |
| SHA3-384 | `fdd363ecb45d60b436b637cc4814e5a737ac659e777cbcc7b1846f84f9bb0fabb7fe80797e96925597138f09ab4a0125` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T101863382E4C187A3D355C9717D6386E53F68EBD79320AB24CF301B904D7EA40E469E6B` |
| SSDEEP | `196608:tTOXHejKmt8jSiW/2FeiysfdMDSyUeYbHcKL805dAe:tTOXHetY/WkysfdYSbftfCe` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_4e1d821d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50"
    family = "unknown"
    file_name = "4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:38:37"
  condition:
    hash.sha256(0, filesize) == "4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50"
}
```

### Sample 65: `4ecc8733de929518`

| Field | Value |
|---|---|
| SHA-256 | `4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64` |
| Family label | `VShell` |
| File name | `4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64.exe` |
| File type | `exe` |
| First seen | `2026-10-01 02:37:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc6af9570ba15a193ead2a12bf374fdd` |
| SHA-1 | `42d16d9d3a4a4a16733f21ff19292442264033e1` |
| SHA-256 | `4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64` |
| SHA3-384 | `ea3e76288df2ce9d7c4cce46ebca905820101b4ccd891f62687c36e3a44b803c9f6fd44c877344090c9ba687fd6c5825` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T13B91D74170B989E7E85D85BB4C0FB8A0B91D740A41C483A74378A5993F3A57BF57CB0E` |
| SSDEEP | `48:6IIF9BlQaexIjWgZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMIj/70cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_065_4ecc8733
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64"
    family = "VShell"
    file_name = "4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:37:56"
  condition:
    hash.sha256(0, filesize) == "4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64"
}
```

### Sample 66: `5fb5bf9ffb35f89c`

| Field | Value |
|---|---|
| SHA-256 | `5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23` |
| Family label | `VShell` |
| File name | `5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23.exe` |
| File type | `exe` |
| First seen | `2026-10-01 02:37:53` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a07e4c39ae11945c629ea630def97482` |
| SHA-1 | `cb4a9203f7f3c37ac51c3a06c26f5f1672c5438a` |
| SHA-256 | `5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23` |
| SHA3-384 | `b94ebe9c1e5abe7a9aa12550b7805d7f2a2fbcba9127b4a8b4e2d7ca708d4ba1ed4aa7e3c0b973cce0800b2f213e5338` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1DA91A5C5F75BE6B6EC1C07F500A379A4C8682E14927C9B464FE16F0C7C111AA3D6DA52` |
| SSDEEP | `48:6I7lwe7WF08SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1Q091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_066_5fb5bf9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23"
    family = "VShell"
    file_name = "5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:37:53"
  condition:
    hash.sha256(0, filesize) == "5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23"
}
```

### Sample 67: `e136fd4421febdf5`

| Field | Value |
|---|---|
| SHA-256 | `e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9` |
| Family label | `VShell` |
| File name | `e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9.exe` |
| File type | `exe` |
| First seen | `2026-10-01 02:37:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bb59f277287c1f27e7970121ba15d97` |
| SHA-1 | `6496606dd776b69afa00ed98aab6c57d31fbb891` |
| SHA-256 | `e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9` |
| SHA3-384 | `5bdcf9078fe7bb2013a758b392bfdb3b6d84f83c637e2048ed6059eb369429704c62a40c186f68bb7d5c23f36d751791` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T15591A5C5F75BE6B2EC1C07F500A379A4C8682E14927C9B464FE16F0C7C111AA3D6DA52` |
| SSDEEP | `48:6I7lwe7WTa08SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1b091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_067_e136fd44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9"
    family = "VShell"
    file_name = "e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:37:47"
  condition:
    hash.sha256(0, filesize) == "e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9"
}
```

### Sample 68: `df5ca1884dc8dd85`

| Field | Value |
|---|---|
| SHA-256 | `df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2` |
| Family label | `unknown` |
| File name | `df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2.bin` |
| File type | `ps1` |
| First seen | `2026-10-01 02:27:50` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `918ad3516e0ef9d896bc75a31a81d86e` |
| SHA-1 | `e3cb02771517a6001c23f5a3f8a5d8ef6761690b` |
| SHA-256 | `df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2` |
| SHA3-384 | `d291ba5167d5cb54dc29bebcab556a4c11f1cdd99e0040fcd058302c8de161b56760f9698b5352aa7bf94d2b0d555f1a` |
| TLSH | `T16276E0334A13BCEE3B7E2D84D4002D451C2C2E9797648658FB8835BB76E9294DF2E5B4` |
| SSDEEP | `49152:OuKgLhKqcYxa1yZbtLfMRomdaARfM+1CjVUy4Jd/hvQRN0ynJT8rY7ANAWdFVFQ9:h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_df5ca188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2"
    family = "unknown"
    file_name = "df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2.bin"
    file_type = "ps1"
    first_seen = "2026-10-01 02:27:50"
  condition:
    hash.sha256(0, filesize) == "df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2"
}
```

### Sample 69: `3bb89c9e7eff35cd`

| Field | Value |
|---|---|
| SHA-256 | `3bb89c9e7eff35cd476e57b77412497cacd3833cf8d7f7139f6671a1284ac16c` |
| Family label | `Formbook` |
| File name | `Q88_Manas_2026.01.10.com` |
| File type | `exe` |
| First seen | `2026-10-01 02:26:31` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `986f49b76d3d7dfcaa44ccefa6bc3ae0` |
| SHA-1 | `b005bbb4ac1b175ee12d5e1a76ea48f81b266858` |
| SHA-256 | `3bb89c9e7eff35cd476e57b77412497cacd3833cf8d7f7139f6671a1284ac16c` |
| SHA3-384 | `bff12b6c36cf0f4ef43983710bbbd27dfbe1f3e41a98a680b1af3b419829ea9edc5c0122d549fa959024f86e4aa3556a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18305F114AAABDC13C5B2073589E0E27103F19D4AF921D35B4FFA6DD73A12BC658C8693` |
| SSDEEP | `12288:7btgaTd9X5xkUhCtQpF3ZWR5Lv7kPGztku1Y3EquzkPMczoEyG7J/ZiUJy:RpFYR5LvoPIku2pscEEyINJ` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_069_3bb89c9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bb89c9e7eff35cd476e57b77412497cacd3833cf8d7f7139f6671a1284ac16c"
    family = "Formbook"
    file_name = "Q88_Manas_2026.01.10.com"
    file_type = "exe"
    first_seen = "2026-10-01 02:26:31"
  condition:
    hash.sha256(0, filesize) == "3bb89c9e7eff35cd476e57b77412497cacd3833cf8d7f7139f6671a1284ac16c"
}
```

### Sample 70: `935f2d6a19b54943`

| Field | Value |
|---|---|
| SHA-256 | `935f2d6a19b549430c702863aa0f563c42b0dbaca4cde8d6903e70843858dcf5` |
| Family label | `AsyncRAT` |
| File name | `POs 2701789 & 2701790.JS.js` |
| File type | `js` |
| First seen | `2026-10-01 02:25:05` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, js, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cab14ada8d02d03e3fb90d42f8e66a27` |
| SHA-1 | `0dd8a2b82cdcf98f0c99b05796e2d3aab99989af` |
| SHA-256 | `935f2d6a19b549430c702863aa0f563c42b0dbaca4cde8d6903e70843858dcf5` |
| SHA3-384 | `0b8b40aa72468215e578610e7f2ddd27d2eac6af2eaa3dbae7c575788f3e8e0ba88fd1596a8ce6a223bc1bddea56f796` |
| TLSH | `T169C5E5814F0B9472B23D271CC172A9A4150AE01762F5DF3E317862673B6C917A39FBE6` |
| SSDEEP | `49152:Sd+oyW7OKPUbSTND/uxWnANE69yjrgD3/eiwDmNz7HF2PIfvxdp32DgPGDMng/lk:Sgot7OKPUbSTND/uxWnANE69yjr+WiwE` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_070_935f2d6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935f2d6a19b549430c702863aa0f563c42b0dbaca4cde8d6903e70843858dcf5"
    family = "AsyncRAT"
    file_name = "POs 2701789 & 2701790.JS.js"
    file_type = "js"
    first_seen = "2026-10-01 02:25:05"
  condition:
    hash.sha256(0, filesize) == "935f2d6a19b549430c702863aa0f563c42b0dbaca4cde8d6903e70843858dcf5"
}
```

### Sample 71: `b02d58f230484452`

| Field | Value |
|---|---|
| SHA-256 | `b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62` |
| Family label | `Mirai` |
| File name | `b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62` |
| File type | `elf` |
| First seen | `2026-10-01 02:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74d0edfba661c239b958ed4d15c51a30` |
| SHA-1 | `9fa2d5700a0601e14eba5540fe2627dd7b6d313d` |
| SHA-256 | `b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62` |
| SHA3-384 | `c79f3d4c00adf83bbf83deeb6be79c2032dc5e46472ecb8a0f2ce391a00e319a126064fef6caa7d78bbbf664dbdba011` |
| TLSH | `T14444398AFD80AF25D5C5267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJH:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_b02d58f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62"
    family = "Mirai"
    file_name = "b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62"
    file_type = "elf"
    first_seen = "2026-10-01 02:17:14"
  condition:
    hash.sha256(0, filesize) == "b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62"
}
```

### Sample 72: `72ea940b351560c2`

| Field | Value |
|---|---|
| SHA-256 | `72ea940b351560c210c6c8a89171e43b932c99089985b7fcc85f58a8910eb2c6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-01 02:15:03` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6d86b9f47be558e7f2ddd8670a73459` |
| SHA-1 | `4b705ee2ade8029cb01d183622a6c49233e12598` |
| SHA-256 | `72ea940b351560c210c6c8a89171e43b932c99089985b7fcc85f58a8910eb2c6` |
| SHA3-384 | `3e35aa616c5cb506956aa5601600a9007f24f3036713547c7d97508e286fb2622e8d6b271314c53500f91ac99aa2c42b` |
| IMPHASH | `236020b6933db95bf7b1f9b596abade9` |
| TLSH | `T14B94F837CBAA50D9F82FC13CD6DCB129F5627C48413CFABF9A5886531B31A90522D74A` |
| SSDEEP | `6144:AHbSCCi87yMG6IHK6DKAIM9GjTvqSgnSo+8OnZpvkCN+B1/EjKR9eIdZ:A7Y7W36+Kx8ao3C1+BqjK3t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_72ea940b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72ea940b351560c210c6c8a89171e43b932c99089985b7fcc85f58a8910eb2c6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-01 02:15:03"
  condition:
    hash.sha256(0, filesize) == "72ea940b351560c210c6c8a89171e43b932c99089985b7fcc85f58a8910eb2c6"
}
```

### Sample 73: `0714651541a17ca4`

| Field | Value |
|---|---|
| SHA-256 | `0714651541a17ca4cd54ccc018d23b02aaf248d9d7ea5e6dab507ecef3c8e699` |
| Family label | `Mirai` |
| File name | `f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6` |
| File type | `elf` |
| First seen | `2026-10-01 01:29:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccef2cd5bfd5e80c9c683d4ec81d7d14` |
| SHA-1 | `ed1c5033cb20894bd77a7f95043574901ea90035` |
| SHA-256 | `0714651541a17ca4cd54ccc018d23b02aaf248d9d7ea5e6dab507ecef3c8e699` |
| SHA3-384 | `5fb09eeb72a41a379869e64cbbcdc845ce58a3a96a031f5a8c25b80e16354d79cee7737de961d0cccd01de0cd00b6789` |
| TLSH | `T190B44A87A9C044FDC0C9C034439FA2379A76F45C5239BB9B1BC1EF663965EA0A72E750` |
| TELFHASH | `t1ccb15ab018b9b5b0b2c5c940b216f97a9a3240d267ec75705a36bc95dfcaec14ca3c67` |
| SSDEEP | `6144:8AmniXLqmLhwZXPenrTz5iMnXPsdKLI9tNiddL6KxtbEzs3uwoTxWp2:8OemLhwZXmfQMXWFk6yEzszp2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_07146515
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0714651541a17ca4cd54ccc018d23b02aaf248d9d7ea5e6dab507ecef3c8e699"
    family = "Mirai"
    file_name = "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
    file_type = "elf"
    first_seen = "2026-10-01 01:29:20"
  condition:
    hash.sha256(0, filesize) == "0714651541a17ca4cd54ccc018d23b02aaf248d9d7ea5e6dab507ecef3c8e699"
}
```

### Sample 74: `f5d5e0711b83f267`

| Field | Value |
|---|---|
| SHA-256 | `f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6` |
| Family label | `Mirai` |
| File name | `f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6` |
| File type | `elf` |
| First seen | `2026-10-01 01:28:17` |
| Reporter | `theodore_brucker` |
| Tags | `cowrie, elf, honeypot, Mirai, ssh, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf4583046ea5e7f48559ab7269256cee` |
| SHA-1 | `6f6974b126c17e3b104bbdd76f21194ba440a255` |
| SHA-256 | `f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6` |
| SHA3-384 | `5668ed723906c85afc652a92c156ccda61d90a06aec4870575ed080a180ca5269b992e542321dd89a819bede4ffe9c75` |
| TLSH | `T10724124763E92E55F645087AA1314BDF8CA4760B87E16C2FD8F998C08CB59E30DEC823` |
| SSDEEP | `6144:k+tiyRsMnlWKI2V7J9hol9aBbbHToaDkPc2H8HZ:FtiyRsMnAKI+hol9adToaDMhHWZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_f5d5e071
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
    family = "Mirai"
    file_name = "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
    file_type = "elf"
    first_seen = "2026-10-01 01:28:17"
  condition:
    hash.sha256(0, filesize) == "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
}
```

### Sample 75: `0105b8528e478ccf`

| Field | Value |
|---|---|
| SHA-256 | `0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475` |
| Family label | `CoinMiner` |
| File name | `0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475` |
| File type | `gz` |
| First seen | `2026-10-01 01:25:13` |
| Reporter | `beserko` |
| Tags | `CoinMiner, dota, gz, outlaw, perl-ircbot, shellbot, ssh-worm, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6dbbe8a67e10e0225050db6cc862f7b` |
| SHA-1 | `2075b8fb9d7368d885680c4ce7fb553499973270` |
| SHA-256 | `0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475` |
| SHA3-384 | `1497ce99f514e6c981456c5c89636fa70cba61d8e98aa82c3b01121833b6ecbda5d1555907d943329e2249a5ca5a26e2` |
| TLSH | `T1D70633651DD99B2B1AF0F027F2297470DEF23BB8953D81A477C1EDB199994E24C2C078` |
| SSDEEP | `98304:yqbBX3Dw+oWl9m3RMNVwjsPGITN6qWPKYeHy+jNvQlMZi4:yY5Dw+oSmmTwjsPN5MPFeHy+Rc4` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_075_0105b852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475"
    family = "CoinMiner"
    file_name = "0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475"
    file_type = "gz"
    first_seen = "2026-10-01 01:25:13"
  condition:
    hash.sha256(0, filesize) == "0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475"
}
```

### Sample 76: `cd1920655fb815cd`

| Field | Value |
|---|---|
| SHA-256 | `cd1920655fb815cd6fd2ef89229a2624c3ed389da33ed33efcb8da3c654455e6` |
| Family label | `Mirai` |
| File name | `cd1920655fb815cd.bin` |
| File type | `elf` |
| First seen | `2026-10-01 01:25:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0197eaf0ccca8e7e700f3db5adbb5267` |
| SHA-1 | `4824963d44886d11f70aa68eb3fdb761397ff274` |
| SHA-256 | `cd1920655fb815cd6fd2ef89229a2624c3ed389da33ed33efcb8da3c654455e6` |
| SHA3-384 | `c83e0cae372244a6a6d50183cdb8a24f71bf82a2d2d63693e756054c3a318521f51d9794c81716678dc881757afea548` |
| TLSH | `T1B3B48D03A7B7E4B1D4A142B1215557B94872D8B315B7E98FEFE52D90DE60280F32C3AB` |
| TELFHASH | `t158f1ceb22abd1dec73e0a802c20b6b62ed49d67718d436b249f3659532b3f419e71c35` |
| SSDEEP | `6144:bMWyXOpysgHpDhPb5Fu60krIQUclbytAZ774E2Kxcn+O3gQ2i4GrmWpn:bMWyoOLjjdi+l2Kxcn+O52i4Grm+n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_cd192065
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1920655fb815cd6fd2ef89229a2624c3ed389da33ed33efcb8da3c654455e6"
    family = "Mirai"
    file_name = "cd1920655fb815cd.bin"
    file_type = "elf"
    first_seen = "2026-10-01 01:25:08"
  condition:
    hash.sha256(0, filesize) == "cd1920655fb815cd6fd2ef89229a2624c3ed389da33ed33efcb8da3c654455e6"
}
```

### Sample 77: `212f8f40b7451d92`

| Field | Value |
|---|---|
| SHA-256 | `212f8f40b7451d925ef733cdd8d565d0070082b17f08cee182e150ee42d4783c` |
| Family label | `RemcosRAT` |
| File name | `CONTRACT DRAFT-EGP-25006-SG1-SLO-GS-0349.vbs` |
| File type | `vbs` |
| First seen | `2026-10-01 01:22:56` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1adbefcb603e9f0a5a8d1384499f433` |
| SHA-1 | `89c6bf2879d3e5a897bdd72f1d2b6eec4092dbb0` |
| SHA-256 | `212f8f40b7451d925ef733cdd8d565d0070082b17f08cee182e150ee42d4783c` |
| SHA3-384 | `611b5d2fff659615f7083e7fd214fe0564b48babde0e39957900e145f730d6ac3a4307f1da090fca306d496bba892428` |
| TLSH | `T1C9D36D60ED2402590E471BAAFC940E61CAFC8719562350B6FEE9170EB1165ECE3FF729` |
| SSDEEP | `3072:MoQlca12ucAW4oj2noOZVOE1UCoteBIORwwZpI:M/ouT7i2nBZVO4UCoMIaj3I` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_077_212f8f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "212f8f40b7451d925ef733cdd8d565d0070082b17f08cee182e150ee42d4783c"
    family = "RemcosRAT"
    file_name = "CONTRACT DRAFT-EGP-25006-SG1-SLO-GS-0349.vbs"
    file_type = "vbs"
    first_seen = "2026-10-01 01:22:56"
  condition:
    hash.sha256(0, filesize) == "212f8f40b7451d925ef733cdd8d565d0070082b17f08cee182e150ee42d4783c"
}
```

### Sample 78: `3465860b2626b93d`

| Field | Value |
|---|---|
| SHA-256 | `3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89` |
| Family label | `unknown` |
| File name | `3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89.exe` |
| File type | `exe` |
| First seen | `2026-10-01 01:17:48` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f544e7fb8acc4bbd5968b788e616490` |
| SHA-1 | `f47b36d3d6eb8a3c7eace3952a2c41ad373fdcf3` |
| SHA-256 | `3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89` |
| SHA3-384 | `c9fdaa46b4d6b91e6b9831ed69edbd08232e25005ba7e5b22b03db507b962ae3b01b57e33735ebfb945705775c2316c9` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T1921633C01ADCFC67C0555DF966BB02A3C4F3D68B75B18E89C503696FBD20E56A02EC25` |
| SSDEEP | `98304:tPHVT0eqE/F0jE4ZcnjxbtGqCdvauNPYTmJEIug/r2ml6:th0eqE/+wYqCdumJXpTb6` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_3465860b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89"
    family = "unknown"
    file_name = "3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89.exe"
    file_type = "exe"
    first_seen = "2026-10-01 01:17:48"
  condition:
    hash.sha256(0, filesize) == "3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89"
}
```

### Sample 79: `1d214f5c9a401e6c`

| Field | Value |
|---|---|
| SHA-256 | `1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6` |
| Family label | `Mirai` |
| File name | `1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6` |
| File type | `elf` |
| First seen | `2026-10-01 01:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06227d94ff05ad37c627f5d27cd2dc07` |
| SHA-1 | `73011f2819edc23a0ee153e839942538500353b8` |
| SHA-256 | `1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6` |
| SHA3-384 | `e343608f9a79f92a4ef01033d9f3b3544757389e6a0fa306b2438f0eaaed4f2c1a73a6801cf91d46d795b6de8602c308` |
| TLSH | `T1FCF3198BFD81AE5546D127BBFE2E418A331317B8D2EB71129D141F2877CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSDPt:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_1d214f5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6"
    family = "Mirai"
    file_name = "1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6"
    file_type = "elf"
    first_seen = "2026-10-01 01:17:13"
  condition:
    hash.sha256(0, filesize) == "1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6"
}
```

### Sample 80: `13045b384561af13`

| Field | Value |
|---|---|
| SHA-256 | `13045b384561af13da3cbea5be0440e1939e3765b66fbd43a4f64990f60f072c` |
| Family label | `RemcosRAT` |
| File name | `Final rooming list.js` |
| File type | `js` |
| First seen | `2026-10-01 01:05:07` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3709a659ec2383072b59d4a3b21ad780` |
| SHA-1 | `a0bb88ae877955a7f4e2491a29f33c4a40a68877` |
| SHA-256 | `13045b384561af13da3cbea5be0440e1939e3765b66fbd43a4f64990f60f072c` |
| SHA3-384 | `598bb1a3405d5b4866a3feaf3b17ff610ae657070957056ddb51b6962e0b28e8e9ed9c829efa858e772e0fdc5040611c` |
| TLSH | `T1A1F5025189C03FE4DB79561840BD963EE3B10A9B5C2E694AB73FBD469FB3900830719B` |
| SSDEEP | `24576:0mdk11sAIlMWniVKyJvrp5BiasbOJcbtoEX7hyLRn9EDfJBgss9RH+e7OcLuLY0m:ZkCMTblG6JAy8DfvgsGNyL5NLYvrecH` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_080_13045b38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13045b384561af13da3cbea5be0440e1939e3765b66fbd43a4f64990f60f072c"
    family = "RemcosRAT"
    file_name = "Final rooming list.js"
    file_type = "js"
    first_seen = "2026-10-01 01:05:07"
  condition:
    hash.sha256(0, filesize) == "13045b384561af13da3cbea5be0440e1939e3765b66fbd43a4f64990f60f072c"
}
```

### Sample 81: `46a085ef0b76c648`

| Field | Value |
|---|---|
| SHA-256 | `46a085ef0b76c648832a1e3dfe0cf0a06cd1af5d63cc23095e32e9dabf53e635` |
| Family label | `unknown` |
| File name | `macho_46a085ef0b76.bin` |
| File type | `macho` |
| First seen | `2026-10-01 00:54:34` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2aba49d4c168921b9e9349ee99fe3259` |
| SHA-1 | `32e66417b8f55f100fbc92f35a3d94e47e00d4ec` |
| SHA-256 | `46a085ef0b76c648832a1e3dfe0cf0a06cd1af5d63cc23095e32e9dabf53e635` |
| SHA3-384 | `1c87024e870b30e070b17c729181b5170d69e658fbfba5cb95dcbb8192776d0ec9f253b17cf924bb8837bfdeb05c9341` |
| TLSH | `T1E745F1008F6394DAF48CD7342B374A3B9F326560894856DE72561F889E723E3F26B25D` |
| SSDEEP | `24576:Ex1cfiuXYm81YkOlPGOmURBLGCiqofsCmth66:E74VYyCUGzO9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_46a085ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46a085ef0b76c648832a1e3dfe0cf0a06cd1af5d63cc23095e32e9dabf53e635"
    family = "unknown"
    file_name = "macho_46a085ef0b76.bin"
    file_type = "macho"
    first_seen = "2026-10-01 00:54:34"
  condition:
    hash.sha256(0, filesize) == "46a085ef0b76c648832a1e3dfe0cf0a06cd1af5d63cc23095e32e9dabf53e635"
}
```

### Sample 82: `53a6c8ee1cff71c0`

| Field | Value |
|---|---|
| SHA-256 | `53a6c8ee1cff71c0178eea23371d14a7ab9aa3244307c24d3e2197ede129e9a4` |
| Family label | `GCleaner` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-10-01 00:52:07` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68f6871e441fe3dff29e5ade0db70980` |
| SHA-1 | `888d809f949bab73d5f58176a9be28f0c228509a` |
| SHA-256 | `53a6c8ee1cff71c0178eea23371d14a7ab9aa3244307c24d3e2197ede129e9a4` |
| SHA3-384 | `88fe8749842026a5f4a1896e05bde7a33975b10bbf86404b4c79de003f2e3f2e41517d5af4fc88f1caa46834bac3a927` |
| IMPHASH | `06426283b2b3079382b630b914de88af` |
| TLSH | `T1B0159E22A2B1C437C1B23BFF8D2B52B598AAFE013D3854496FE54D4C0E3B65179253A7` |
| SSDEEP | `24576:R1EmyAyseR6UqDBwcm0zGLANwwL2u9IF61:R1/y/skKiuKk` |
| ICON-DHASH | `399998ecd4d46c0e` |

#### Technical Assessment

- The sample is tracked as `GCleaner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GCleaner_082_53a6c8ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53a6c8ee1cff71c0178eea23371d14a7ab9aa3244307c24d3e2197ede129e9a4"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-10-01 00:52:07"
  condition:
    hash.sha256(0, filesize) == "53a6c8ee1cff71c0178eea23371d14a7ab9aa3244307c24d3e2197ede129e9a4"
}
```

### Sample 83: `29fa6a78fe837184`

| Field | Value |
|---|---|
| SHA-256 | `29fa6a78fe8371844fc5e4492fe9368021e562ba0d413729204c17951491e7a1` |
| Family label | `Mirai` |
| File name | `0dddc309b0d30ccc.bin` |
| File type | `elf` |
| First seen | `2026-10-01 00:26:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `976091aa0b992854203d8de248299d2c` |
| SHA-1 | `1f69fbfd4053b02c0e8a26c83ba4b345855baf24` |
| SHA-256 | `29fa6a78fe8371844fc5e4492fe9368021e562ba0d413729204c17951491e7a1` |
| SHA3-384 | `00973d60de0bab74632ab4dc5c11143b3b4e2a0e1508c4ae81943a33ebcfc76aaf8064ffc981155fb9ce30ae32d9d8b7` |
| TLSH | `T1E9C43B80FACB44F6D5078C70806AF33F8B3197258025D66EEFD4EF26EE27651522A395` |
| TELFHASH | `t10cc156b321b9a8d867f0590083ab7210de5bd83726d0347619e37958e633e039f36db9` |
| SSDEEP | `12288:cf3lpCKmsIhjg+NHOpybKORMCcgAoGcjkOx1XG7nGNO:cf3HssIhjg+NHOpymORMLoGrOx1W7GN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_29fa6a78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29fa6a78fe8371844fc5e4492fe9368021e562ba0d413729204c17951491e7a1"
    family = "Mirai"
    file_name = "0dddc309b0d30ccc.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:26:19"
  condition:
    hash.sha256(0, filesize) == "29fa6a78fe8371844fc5e4492fe9368021e562ba0d413729204c17951491e7a1"
}
```

### Sample 84: `6a3a79fb869e2ea3`

| Field | Value |
|---|---|
| SHA-256 | `6a3a79fb869e2ea322090841822ceae3725de2441546e45cdabe82ef763d7cd7` |
| Family label | `Mirai` |
| File name | `6a3a79fb869e2ea3.bin` |
| File type | `elf` |
| First seen | `2026-10-01 00:25:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d749dca80f9bf3693ebd8c7e030e7eb` |
| SHA-1 | `eaf48939d49531bef1fbbca3c2882917d487e716` |
| SHA-256 | `6a3a79fb869e2ea322090841822ceae3725de2441546e45cdabe82ef763d7cd7` |
| SHA3-384 | `7046d0c943b95d34b3ff7bf5cfb6db810ea8e6d4dea9e1418cb277d82dec9e2cece6127a7e5642a48641b833efcfa4ff` |
| TLSH | `T12BD44A55F8809F63C9C52A36F64E866833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKia:YCp7mXtni6aBh321eSiVWK1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_6a3a79fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a3a79fb869e2ea322090841822ceae3725de2441546e45cdabe82ef763d7cd7"
    family = "Mirai"
    file_name = "6a3a79fb869e2ea3.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:57"
  condition:
    hash.sha256(0, filesize) == "6a3a79fb869e2ea322090841822ceae3725de2441546e45cdabe82ef763d7cd7"
}
```

### Sample 85: `0dddc309b0d30ccc`

| Field | Value |
|---|---|
| SHA-256 | `0dddc309b0d30ccc26cc52c0dbda60ea3e447c07a9261c561c0cfe40ebc2f928` |
| Family label | `Mirai` |
| File name | `0dddc309b0d30ccc.bin` |
| File type | `elf` |
| First seen | `2026-10-01 00:25:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8d229f7db55d1f7fb682faae3e101d1` |
| SHA-1 | `6db5cdd590047fa5011c35b2f17986a758e15e45` |
| SHA-256 | `0dddc309b0d30ccc26cc52c0dbda60ea3e447c07a9261c561c0cfe40ebc2f928` |
| SHA3-384 | `b354c3e3038ab0a445cb1b18304d6e6a65a9ed4ce153dd774b50fb505da6ae6738dc24c62e4170d831608f844122c003` |
| TLSH | `T1BA242333984769239E6DD3BC38AEFDD3AF25F0693723490E6947361D863E438A014D65` |
| SSDEEP | `3072:bidL+I4hYDkRoDo6w9Tkm2Fxo0+XQA9J87yA3jvIW8nJKXXcpxA0A9Q9fzxKIhjs:xh6onYfrouhDIW8nJKXXcppkGDnP8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_0dddc309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dddc309b0d30ccc26cc52c0dbda60ea3e447c07a9261c561c0cfe40ebc2f928"
    family = "Mirai"
    file_name = "0dddc309b0d30ccc.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:47"
  condition:
    hash.sha256(0, filesize) == "0dddc309b0d30ccc26cc52c0dbda60ea3e447c07a9261c561c0cfe40ebc2f928"
}
```

### Sample 86: `e8d544cbeeef8a4d`

| Field | Value |
|---|---|
| SHA-256 | `e8d544cbeeef8a4d687a24cba5e390dc0a3a9027e2e78507f0ee8b4c4a8e9b86` |
| Family label | `Mirai` |
| File name | `e8d544cbeeef8a4d.bin` |
| File type | `elf` |
| First seen | `2026-10-01 00:25:40` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e616d5440e04019fb4e407dab56032b1` |
| SHA-1 | `a1837fb83c847114232bfccebe925ed92cfc5fc0` |
| SHA-256 | `e8d544cbeeef8a4d687a24cba5e390dc0a3a9027e2e78507f0ee8b4c4a8e9b86` |
| SHA3-384 | `ab5512ceafb94a56cdc6d9efbb1857f97fcd286dbae8041ee431404ee824874db9e0f5d21945d1597aa0914eb45bd91b` |
| TLSH | `T1C1254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmAv8:KdM4DmUj657yDAme8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_e8d544cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8d544cbeeef8a4d687a24cba5e390dc0a3a9027e2e78507f0ee8b4c4a8e9b86"
    family = "Mirai"
    file_name = "e8d544cbeeef8a4d.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:40"
  condition:
    hash.sha256(0, filesize) == "e8d544cbeeef8a4d687a24cba5e390dc0a3a9027e2e78507f0ee8b4c4a8e9b86"
}
```

### Sample 87: `08116fa61c263e41`

| Field | Value |
|---|---|
| SHA-256 | `08116fa61c263e41459257c950fdda70113a3c7474060f71db98b10e0c5339a0` |
| Family label | `Mirai` |
| File name | `08116fa61c263e41.bin` |
| File type | `elf` |
| First seen | `2026-10-01 00:25:32` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bb61f33f096df779a4094d0bd4617a3` |
| SHA-1 | `c29edeebd914081645704667c0f5449584b910c7` |
| SHA-256 | `08116fa61c263e41459257c950fdda70113a3c7474060f71db98b10e0c5339a0` |
| SHA3-384 | `f15ddfaee493ba02608c3e2a2782eccea56a686d2ab14fa6130951570bf7388baaf11a782b80540d651be90fc0279ba1` |
| TLSH | `T127A49EC2A5408D7EEC85A27A8A1716066131D3E020A35B1FF39FBD6ABE3B1F55931F41` |
| SSDEEP | `12288:HkPJSzRX9SOps7sH7hvGlEUIjnG4Qk0OV7v+0:EPCRX3SsolEUIjnG4lXhr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_08116fa6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08116fa61c263e41459257c950fdda70113a3c7474060f71db98b10e0c5339a0"
    family = "Mirai"
    file_name = "08116fa61c263e41.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:32"
  condition:
    hash.sha256(0, filesize) == "08116fa61c263e41459257c950fdda70113a3c7474060f71db98b10e0c5339a0"
}
```

### Sample 88: `c8f51f05a57025ae`

| Field | Value |
|---|---|
| SHA-256 | `c8f51f05a57025aeae8514642f4cbb134b3c4ce713488cf87c3a4855820e5694` |
| Family label | `Mirai` |
| File name | `c8f51f05a57025ae.bin` |
| File type | `elf` |
| First seen | `2026-10-01 00:25:24` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f977351c3b682ceebcb427c56dd7cd8` |
| SHA-1 | `8420d0b275653facf761119d0f80b5fa1a0258fe` |
| SHA-256 | `c8f51f05a57025aeae8514642f4cbb134b3c4ce713488cf87c3a4855820e5694` |
| SHA3-384 | `193ed01932339eddaf4c4d2e872461ac477a70b1d625505370c31300f849ce3b77ae189454444d9fb652a775c15209f4` |
| TLSH | `T1CAB4BF32C0B66DD5C0735274B8BADAB04B22784051A71DF3AADAD72D0893ED5B72D3B4` |
| SSDEEP | `12288:Il0bkgXwaCHrZFLl9uYww6E76cWpNYTm:JD4FvB6Dfk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_c8f51f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8f51f05a57025aeae8514642f4cbb134b3c4ce713488cf87c3a4855820e5694"
    family = "Mirai"
    file_name = "c8f51f05a57025ae.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:24"
  condition:
    hash.sha256(0, filesize) == "c8f51f05a57025aeae8514642f4cbb134b3c4ce713488cf87c3a4855820e5694"
}
```

### Sample 89: `1c875667079fabc7`

| Field | Value |
|---|---|
| SHA-256 | `1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e` |
| Family label | `unknown` |
| File name | `1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e` |
| File type | `elf` |
| First seen | `2026-10-01 00:18:00` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c550fff2f60387804c18e07456c6b623` |
| SHA-1 | `ed685f8cf6b59a9ffa66c2eb7f17172cb50cfe37` |
| SHA-256 | `1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e` |
| SHA3-384 | `b853a851fec1209cc7c29ff3d295927f9c4366242fe6aec31d7a840c8326411efb9f14f9583d7af1af0445f956e1e84a` |
| TLSH | `T105D31312D3130C4FC02578FA7E2BE65929862E6A24CE409C46F5D67A5FB70C8EDB1713` |
| SSDEEP | `3072:biMYFJvw6Yh0b1gKobtCGCmCRlrisfrYo:fYFJvwe1gKCYVl2sz7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_1c875667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e"
    family = "unknown"
    file_name = "1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e"
    file_type = "elf"
    first_seen = "2026-10-01 00:18:00"
  condition:
    hash.sha256(0, filesize) == "1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e"
}
```

### Sample 90: `f83a026679ba4125`

| Field | Value |
|---|---|
| SHA-256 | `f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33` |
| Family label | `Mirai` |
| File name | `f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33` |
| File type | `elf` |
| First seen | `2026-10-01 00:17:54` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c428847cb3a5ae370e0f04b5c843d455` |
| SHA-1 | `be25d782ed224b2aa60ba6f30a24310c361e6641` |
| SHA-256 | `f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33` |
| SHA3-384 | `1a277998b32d6c1b6e331202ebee6abfcfcc9563a918fcb0796235e32a817119662e1c0b7ae83526ca924122cb62b4fd` |
| TLSH | `T19CD3189FFD81AE6546C0277BFE2E418A331327B4D2DB71139D041F28768A94F0E7A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmJ:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_f83a0266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33"
    family = "Mirai"
    file_name = "f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33"
    file_type = "elf"
    first_seen = "2026-10-01 00:17:54"
  condition:
    hash.sha256(0, filesize) == "f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33"
}
```

### Sample 91: `45db5310a177214d`

| Field | Value |
|---|---|
| SHA-256 | `45db5310a177214d3a38ce54e6a3abd9da05ba456f925886cdab810b396dc528` |
| Family label | `unknown` |
| File name | `update.apk` |
| File type | `apk` |
| First seen | `2026-10-01 00:09:07` |
| Reporter | `adliwahid` |
| Tags | `signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaeff8ad85d2139c0d8b22d22d0533c2` |
| SHA-1 | `55fb7a3aeee843019a0d281bdcf96c242e370d9f` |
| SHA-256 | `45db5310a177214d3a38ce54e6a3abd9da05ba456f925886cdab810b396dc528` |
| SHA3-384 | `ae9dcf8247fd9be1097090a4ca1e3a752e10533685ac2e3e462aecd55d776b17316b204810225060bb3267d97fd26b23` |
| TLSH | `T18D23AE313BBE1D22E66568750369A7721F11D362F5703BFE123252E095C36A4A9F82BC` |
| SSDEEP | `192:F3f0h4MCCN31NsSnaCDambSZhDiucPbRd5nKB8BBrqJeWPUzkUupmrb7gcKl:F3cGMCu3GsbghWpL5nKBST6ig5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_45db5310
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45db5310a177214d3a38ce54e6a3abd9da05ba456f925886cdab810b396dc528"
    family = "unknown"
    file_name = "update.apk"
    file_type = "apk"
    first_seen = "2026-10-01 00:09:07"
  condition:
    hash.sha256(0, filesize) == "45db5310a177214d3a38ce54e6a3abd9da05ba456f925886cdab810b396dc528"
}
```

### Sample 92: `3a5e7a1e5d4394d3`

| Field | Value |
|---|---|
| SHA-256 | `3a5e7a1e5d4394d3a4fce80595dfc03301d3d6cce55094bd34a2de7b1c2c814c` |
| Family label | `unknown` |
| File name | `macho_3a5e7a1e5d43.bin` |
| File type | `macho` |
| First seen | `2026-09-30 23:44:44` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dbb34c2d078ae36a8f41a07594c9b78` |
| SHA-1 | `1b4809095ac9817e4909439f688be3ec4ab9d3bf` |
| SHA-256 | `3a5e7a1e5d4394d3a4fce80595dfc03301d3d6cce55094bd34a2de7b1c2c814c` |
| SHA3-384 | `f02d5db2b4aad8c8de8229b8a3bb1ffd32cd52b7497a06b1ee5cc69290fdf7b508540a335728ec5d9b33f13966d2a43c` |
| TLSH | `T11EC67EB5643CD81ED083E0F87A8B87E27D09F46003B0514737A57F6DBE64E5019ADBAA` |
| SSDEEP | `196608:RfAf4i7PAE9WL62ceJUERzMedZEFggwDmtH3E9WL62ceJUUfzNV:RIwi7PAE9WL62ceJU2zJdZE+gwDm53EW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_3a5e7a1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a5e7a1e5d4394d3a4fce80595dfc03301d3d6cce55094bd34a2de7b1c2c814c"
    family = "unknown"
    file_name = "macho_3a5e7a1e5d43.bin"
    file_type = "macho"
    first_seen = "2026-09-30 23:44:44"
  condition:
    hash.sha256(0, filesize) == "3a5e7a1e5d4394d3a4fce80595dfc03301d3d6cce55094bd34a2de7b1c2c814c"
}
```

### Sample 93: `474348c456e836f0`

| Field | Value |
|---|---|
| SHA-256 | `474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1` |
| Family label | `Mirai` |
| File name | `474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1` |
| File type | `elf` |
| First seen | `2026-09-30 23:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ebf46154e080b79bdc51caa814ac54c` |
| SHA-1 | `626a6779383e36fd6dbf9983434e9918f1ba0d50` |
| SHA-256 | `474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1` |
| SHA3-384 | `05b0d2c7d803ce5b8aa28c1e370cbaa956b0c70d935db857441a9b30150a80a843b83d66a46725b6935ecd155b034a9a` |
| TLSH | `T1EBC3098BBC91EE6546C0277BFE2E418E331327B4D1DF71139D141F68B68A94F0E6A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaG:T2s/gAWuboqsJ9xcJxspJBqQgTuaG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_474348c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1"
    family = "Mirai"
    file_name = "474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1"
    file_type = "elf"
    first_seen = "2026-09-30 23:17:13"
  condition:
    hash.sha256(0, filesize) == "474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1"
}
```

### Sample 94: `695d1993072310f6`

| Field | Value |
|---|---|
| SHA-256 | `695d1993072310f65fe068c507235ccd184a4c9a876d6179388778d1490ab39d` |
| Family label | `unknown` |
| File name | `1` |
| File type | `elf` |
| First seen | `2026-09-30 23:14:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7985ac71dbfb8cb52520f5959187676f` |
| SHA-1 | `6f3852011f9ea44fc1419701e9db68f13e8ec31a` |
| SHA-256 | `695d1993072310f65fe068c507235ccd184a4c9a876d6179388778d1490ab39d` |
| SHA3-384 | `8ecd020a1a68fb8f2162b4ad6dbe88085d2ca8b34d2efe7553b53dbce679b2e4d8753e8e169f240a634864fed50a3bc9` |
| TLSH | `T14FA423FAEE271EB1890BD1B24AB41C506D68B61F94E69B390D055F98B8D7036C23FA41` |
| SSDEEP | `12288:dzKzsGr1AtQMXqgUkWxtQ54z/M6U469Pjk18hThU61/wNw7m9:VQ2tavxu54zrUnPA189xK6m9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_695d1993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "695d1993072310f65fe068c507235ccd184a4c9a876d6179388778d1490ab39d"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-30 23:14:48"
  condition:
    hash.sha256(0, filesize) == "695d1993072310f65fe068c507235ccd184a4c9a876d6179388778d1490ab39d"
}
```

### Sample 95: `c2791fd5366675b9`

| Field | Value |
|---|---|
| SHA-256 | `c2791fd5366675b995d332565998f6fc84bbcca2af6567f8cc21f6aabd8d54b1` |
| Family label | `RemcosRAT` |
| File name | `Complete Set of Documents For Bill of Lading - 238591458.vbs` |
| File type | `vbs` |
| First seen | `2026-09-30 23:13:37` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d3014e140e048062575fbb4ef1f00ba` |
| SHA-1 | `d1ddfb29109c58afd1956632ad5cd0bd239ceb14` |
| SHA-256 | `c2791fd5366675b995d332565998f6fc84bbcca2af6567f8cc21f6aabd8d54b1` |
| SHA3-384 | `75f2dc88b28a957dbfadb485a76a5db892cf2790d8da0eda28411431a7ebeb20b93667f753addea5a1a887473be5b683` |
| TLSH | `T130D34B60DD3402594E471BADFCA50A62CABC821E922254B6FEDD170D6106DFCE3FE62D` |
| SSDEEP | `3072:EKBU6YZMsyHxA8ea3DVn+OJVOa1pRmWYBIORwwJf:E7ms2Cja3xnTJVO+pRmzIajJf` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_095_c2791fd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2791fd5366675b995d332565998f6fc84bbcca2af6567f8cc21f6aabd8d54b1"
    family = "RemcosRAT"
    file_name = "Complete Set of Documents For Bill of Lading - 238591458.vbs"
    file_type = "vbs"
    first_seen = "2026-09-30 23:13:37"
  condition:
    hash.sha256(0, filesize) == "c2791fd5366675b995d332565998f6fc84bbcca2af6567f8cc21f6aabd8d54b1"
}
```

### Sample 96: `c3c207857f29cba4`

| Field | Value |
|---|---|
| SHA-256 | `c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d` |
| Family label | `unknown` |
| File name | `c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d.exe` |
| File type | `exe` |
| First seen | `2026-09-30 23:12:07` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2a97351e943404f229f13c68ddf47e0` |
| SHA-1 | `ee4b39fe5e5cb32da6eee36c6ef5d8ac64d7cc3e` |
| SHA-256 | `c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d` |
| SHA3-384 | `4ac3def15cbdd92f6a1c86e1eaf70b8db4edbb5417c9c3e57ff7a1b345df7d7578c64e8af0648b5d1c5cebc72ebf08ed` |
| IMPHASH | `f4d1e4cd7416ef83f79f7c6a038875b3` |
| TLSH | `T1A9B4122CAF258CF6E93244348597FA7B5638AC70CD6A5A4FD7450A73DC731E6DA0B202` |
| SSDEEP | `12288:pfI4M/scS/du82pr0knXpvC0pR1yGx1fhXkd2YwQFp0:p3hu82pr0uphR16dwQA` |
| ICON-DHASH | `1026261a13231e00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_c3c20785
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d"
    family = "unknown"
    file_name = "c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d.exe"
    file_type = "exe"
    first_seen = "2026-09-30 23:12:07"
  condition:
    hash.sha256(0, filesize) == "c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d"
}
```

### Sample 97: `1530fcebb5e06932`

| Field | Value |
|---|---|
| SHA-256 | `1530fcebb5e0693234aee367915cf7485c66477b26c5fc70d367bef05b3b1872` |
| Family label | `unknown` |
| File name | `05f3c4c98cf6ebdc972e7d196d0a3ef0` |
| File type | `dll` |
| First seen | `2026-09-30 23:10:44` |
| Reporter | `AmStaff7021` |
| Tags | `dionaea, dll, exe, honeypot, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05f3c4c98cf6ebdc972e7d196d0a3ef0` |
| SHA-256 | `1530fcebb5e0693234aee367915cf7485c66477b26c5fc70d367bef05b3b1872` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_1530fceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1530fcebb5e0693234aee367915cf7485c66477b26c5fc70d367bef05b3b1872"
    family = "unknown"
    file_name = "05f3c4c98cf6ebdc972e7d196d0a3ef0"
    file_type = "dll"
    first_seen = "2026-09-30 23:10:44"
  condition:
    hash.sha256(0, filesize) == "1530fcebb5e0693234aee367915cf7485c66477b26c5fc70d367bef05b3b1872"
}
```

### Sample 98: `6b98f26a10b2c3c7`

| Field | Value |
|---|---|
| SHA-256 | `6b98f26a10b2c3c75cfdbd66d983a72785b71fd1ad4f16b7d7e660fcf0f99122` |
| Family label | `Mirai` |
| File name | `loligang.arm7` |
| File type | `elf` |
| First seen | `2026-09-30 22:50:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ab8c114533211df5ce1dce268fc39ed` |
| SHA-1 | `f536cf5c8303bc65f2438eedaed165e9846b327b` |
| SHA-256 | `6b98f26a10b2c3c75cfdbd66d983a72785b71fd1ad4f16b7d7e660fcf0f99122` |
| SHA3-384 | `2940871110ed5673f09aedae956811f0c90f6122fc3106686f21bf21d81665606db86e0f267694fcc22331c2fc2cac5f` |
| TLSH | `T1A7045D42DA418E13C0D6177ABAEF424933239764E3DB73069D18AFB43F8669E0E77605` |
| TELFHASH | `t1f93100b2572a92162b74ca9cccec63b601189b125346ff33ef2184ec641a09df939c5f` |
| SSDEEP | `3072:t0ieQa6v79mrsplDKZUlQBKXAVanSX+F8Jyve95WZjwUags8q65xHuWQiesdaiQi:t0IXj9mrsplDKZUlQBKXAVanSX+F8JyF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_6b98f26a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b98f26a10b2c3c75cfdbd66d983a72785b71fd1ad4f16b7d7e660fcf0f99122"
    family = "Mirai"
    file_name = "loligang.arm7"
    file_type = "elf"
    first_seen = "2026-09-30 22:50:58"
  condition:
    hash.sha256(0, filesize) == "6b98f26a10b2c3c75cfdbd66d983a72785b71fd1ad4f16b7d7e660fcf0f99122"
}
```

### Sample 99: `f23991766ddae548`

| Field | Value |
|---|---|
| SHA-256 | `f23991766ddae548a8d22c65c1741b62d349f22506d2293a9e39bc9aa8e188c9` |
| Family label | `Mirai` |
| File name | `loligang.arm6` |
| File type | `elf` |
| First seen | `2026-09-30 22:44:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c51428d64b855919b74d44e5c53f4502` |
| SHA-1 | `14d7578c30f05c2a7937f343b42cf4b7854a7076` |
| SHA-256 | `f23991766ddae548a8d22c65c1741b62d349f22506d2293a9e39bc9aa8e188c9` |
| SHA3-384 | `8603e55557d9318d97fe18adc46dc90c6666605dc6d2720492877cf0fbf60f94006f89109fe3e4c7c3c8f17fdf4d9385` |
| TLSH | `T104B34A81BC819A12C5D513BAFA2E018E331317BCE2DEB2539D14AF2477CA86F0E7B555` |
| TELFHASH | `t1fe11edc29b9459dd28c04324caac176288e835f8af42b466e72c6b9b8357dc13028836` |
| SSDEEP | `3072:6JQ7uupc9mrsplDKZU9QBKXAVansX+F8Jyvquo6x2UzacOZo/rvDqHZfbr3:6Jnua9mrsplDKZU9QBKXAVansX+F8JyY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_f2399176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f23991766ddae548a8d22c65c1741b62d349f22506d2293a9e39bc9aa8e188c9"
    family = "Mirai"
    file_name = "loligang.arm6"
    file_type = "elf"
    first_seen = "2026-09-30 22:44:54"
  condition:
    hash.sha256(0, filesize) == "f23991766ddae548a8d22c65c1741b62d349f22506d2293a9e39bc9aa8e188c9"
}
```

### Sample 100: `8ae3ecc64619fb0e`

| Field | Value |
|---|---|
| SHA-256 | `8ae3ecc64619fb0ebee9bd539d757cd22b10595a71d5fb24f33688f93ec664da` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-30 22:43:04` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8cb358489b0e3163498b8d612219f3f` |
| SHA-1 | `626d350b6312152cc62d97f944fb5276533454db` |
| SHA-256 | `8ae3ecc64619fb0ebee9bd539d757cd22b10595a71d5fb24f33688f93ec664da` |
| SHA3-384 | `659ce2b0db6d27f3c12920b8f9e92e9a20ec97bda47b16665c0acedb1e015f85e4730558c3747ad55b82254e356059ee` |
| IMPHASH | `dccb5acc1e2fed10ec52d2fcdbbceaaa` |
| TLSH | `T15DF516D8DE6F9CE1AD5ADA3B9835025B63F03DC244F9FB65161AAE1168335EB3C30046` |
| SSDEEP | `24576:TJ685Fj5nX5/YzXj/ZyzBNhd52m+WGZdiu8qsJo3AJu8qjyMbTr8I1XUfWJ:bpo4NJDO/iCaJyZbTgNf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_8ae3ecc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ae3ecc64619fb0ebee9bd539d757cd22b10595a71d5fb24f33688f93ec664da"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 22:43:04"
  condition:
    hash.sha256(0, filesize) == "8ae3ecc64619fb0ebee9bd539d757cd22b10595a71d5fb24f33688f93ec664da"
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
 * Generated: 2026-10-01T06:06:56.898933+00:00
 */

rule MalwareBazaar_unknown_001_64707556
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64707556ee186bd56e9f73f70164114b1e55f0448553f7e9c709e0bef42ad834"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-10-01 06:04:07"
  condition:
    hash.sha256(0, filesize) == "64707556ee186bd56e9f73f70164114b1e55f0448553f7e9c709e0bef42ad834"
}

rule MalwareBazaar_Mirai_002_6b4b3724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-10-01 06:04:05"
  condition:
    hash.sha256(0, filesize) == "6b4b3724c21b93a773823853c561d4da1b2d216879f30d40c20965cbef66f50e"
}

rule MalwareBazaar_unknown_003_b28344e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b"
    family = "unknown"
    file_name = "b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b.exe"
    file_type = "exe"
    first_seen = "2026-10-01 06:02:39"
  condition:
    hash.sha256(0, filesize) == "b28344e12d3576a96f94c6144a6b7c355eded7acacc1126d1a9148dec177768b"
}

rule MalwareBazaar_unknown_004_446150a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446150a7841e85746ef4209c550853445d4ff2625242b2f2d62c0c34f30756f8"
    family = "unknown"
    file_name = "db14c885f4ffd5baf2398ec94f529090.exe"
    file_type = "exe"
    first_seen = "2026-10-01 06:01:47"
  condition:
    hash.sha256(0, filesize) == "446150a7841e85746ef4209c550853445d4ff2625242b2f2d62c0c34f30756f8"
}

rule MalwareBazaar_unknown_005_a0b05657
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0b056570801f3bc3469f3f2f28bd3952fa9e94648797a46656fc16a1fb87303"
    family = "unknown"
    file_name = "DHL MNLR003179244.js"
    file_type = "js"
    first_seen = "2026-10-01 05:56:39"
  condition:
    hash.sha256(0, filesize) == "a0b056570801f3bc3469f3f2f28bd3952fa9e94648797a46656fc16a1fb87303"
}

rule MalwareBazaar_unknown_006_b5b7e273
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5b7e2731de6384bdd8a82956240cb21e08fc2c8d50cd71dee06823169464ca0"
    family = "unknown"
    file_name = "f286eb73f3fc6ca9aa332bf355e6533b"
    file_type = "dll"
    first_seen = "2026-10-01 05:30:41"
  condition:
    hash.sha256(0, filesize) == "b5b7e2731de6384bdd8a82956240cb21e08fc2c8d50cd71dee06823169464ca0"
}

rule MalwareBazaar_unknown_007_586d9827
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550"
    family = "unknown"
    file_name = "586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:28:00"
  condition:
    hash.sha256(0, filesize) == "586d98277d3edc99e37280a970d9a1cd1ad38cf22f8a77648c3bd1212387b550"
}

rule MalwareBazaar_RemusStealer_008_80bd7181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25"
    family = "RemusStealer"
    file_name = "80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:27:35"
  condition:
    hash.sha256(0, filesize) == "80bd71812ea7c35634f5f590d80ebdba1ea9f882e8691e9854b9b62916ee4f25"
}

rule MalwareBazaar_Mirai_009_6e50beb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b"
    family = "Mirai"
    file_name = "6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b"
    file_type = "elf"
    first_seen = "2026-10-01 05:17:13"
  condition:
    hash.sha256(0, filesize) == "6e50beb2039190f8101a9e2f43b3e3952cf97330e906e36f290dbbcfecf9c30b"
}

rule MalwareBazaar_unknown_010_a4adf7d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9"
    family = "unknown"
    file_name = "a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:14:48"
  condition:
    hash.sha256(0, filesize) == "a4adf7d173b6e5b14504a3d9217591aa515d91af4e9144d73f44db98d7d280b9"
}

rule MalwareBazaar_Mirai_011_dd50f6da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd50f6da0e5f8d6c8c10df954376162882aa1455e5e501ad4bc71cebc63868a9"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-01 05:14:25"
  condition:
    hash.sha256(0, filesize) == "dd50f6da0e5f8d6c8c10df954376162882aa1455e5e501ad4bc71cebc63868a9"
}

rule MalwareBazaar_Mirai_012_0dc9d5b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc9d5b5d7b478e8fd56f0794c21a1b1e3b09cd47d766c7779c301aa71c8ef33"
    family = "Mirai"
    file_name = "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf.elf"
    file_type = "elf"
    first_seen = "2026-10-01 05:14:22"
  condition:
    hash.sha256(0, filesize) == "0dc9d5b5d7b478e8fd56f0794c21a1b1e3b09cd47d766c7779c301aa71c8ef33"
}

rule MalwareBazaar_Mirai_013_db02b421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db02b4218c861714def17679d47d00ff0287b9100839a6fdc27b58562cdd45f3"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-01 05:14:14"
  condition:
    hash.sha256(0, filesize) == "db02b4218c861714def17679d47d00ff0287b9100839a6fdc27b58562cdd45f3"
}

rule MalwareBazaar_Mirai_014_7e9a7d47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf"
    family = "Mirai"
    file_name = "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf.elf"
    file_type = "elf"
    first_seen = "2026-10-01 05:13:59"
  condition:
    hash.sha256(0, filesize) == "7e9a7d470aaad74302dc7c2f50391c8c420ed91cb2e1e22bba260c12e2f210bf"
}

rule MalwareBazaar_unknown_015_dbb93fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916"
    family = "unknown"
    file_name = "dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:13:11"
  condition:
    hash.sha256(0, filesize) == "dbb93fb26bf429a76cb994bcf4aeb75b671af551ea63b87dc1f979940e8a2916"
}

rule MalwareBazaar_AgentTesla_016_e1b30def
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1b30def98704eda7ca2abb7aea902cdc98be471fe3ace60e6017e1588413363"
    family = "AgentTesla"
    file_name = "statement-103217.js"
    file_type = "js"
    first_seen = "2026-10-01 05:13:06"
  condition:
    hash.sha256(0, filesize) == "e1b30def98704eda7ca2abb7aea902cdc98be471fe3ace60e6017e1588413363"
}

rule MalwareBazaar_VShell_017_1c93d705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d"
    family = "VShell"
    file_name = "1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d.exe"
    file_type = "exe"
    first_seen = "2026-10-01 05:12:45"
  condition:
    hash.sha256(0, filesize) == "1c93d7059eed451f247cb2a91ab76b0f0fc7baea8e1c190f59dadc94e00da13d"
}

rule MalwareBazaar_RemcosRAT_018_7250576a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7250576a3cb7164bf383d89683267604dd1a5d36e1a35f22b5bef2d9f29402e5"
    family = "RemcosRAT"
    file_name = "(TWN26100200.TWN26100218.TWN26100222.TWN26090662.TWN26100226.TWN26100262.TWN26100313).exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:43:23"
  condition:
    hash.sha256(0, filesize) == "7250576a3cb7164bf383d89683267604dd1a5d36e1a35f22b5bef2d9f29402e5"
}

rule MalwareBazaar_unknown_019_da9bb542
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc"
    family = "unknown"
    file_name = "da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:42:43"
  condition:
    hash.sha256(0, filesize) == "da9bb5422c3fc73fc27daa8f10c715b27090f883811a6ba7bd84d3228a64e0fc"
}

rule MalwareBazaar_unknown_020_7c77f80c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c77f80c4cb795f8d19a1c90340ff39012c1617d8b4f7cfe7cb3b8f7a14521c8"
    family = "unknown"
    file_name = "mbupload-0o19xzqz.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:17"
  condition:
    hash.sha256(0, filesize) == "7c77f80c4cb795f8d19a1c90340ff39012c1617d8b4f7cfe7cb3b8f7a14521c8"
}

rule MalwareBazaar_unknown_021_90c930f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90c930f706880abf2b7b6da83c694884ef4852716c6af24aa6c636a830d05617"
    family = "unknown"
    file_name = "mbupload-dyugeu5n.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:13"
  condition:
    hash.sha256(0, filesize) == "90c930f706880abf2b7b6da83c694884ef4852716c6af24aa6c636a830d05617"
}

rule MalwareBazaar_unknown_022_2408a722
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2408a722990b81312752796ff89b8e3660421f8c09bdd9fe2bf412a9bb89ce3f"
    family = "unknown"
    file_name = "mbupload-rmslsmtw.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:07"
  condition:
    hash.sha256(0, filesize) == "2408a722990b81312752796ff89b8e3660421f8c09bdd9fe2bf412a9bb89ce3f"
}

rule MalwareBazaar_unknown_023_a330fdc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a330fdc4266c2163a661aab758c06d52de0e923872dfb95f16f371183d4280f0"
    family = "unknown"
    file_name = "mbupload-r7gxy7lq.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:42:01"
  condition:
    hash.sha256(0, filesize) == "a330fdc4266c2163a661aab758c06d52de0e923872dfb95f16f371183d4280f0"
}

rule MalwareBazaar_unknown_024_37118840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "371188405bfded45d2b7d0259c204611064d3bb4da5364ed70ce1b33e0f70fff"
    family = "unknown"
    file_name = "mbupload-_os2ruh8.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:41:54"
  condition:
    hash.sha256(0, filesize) == "371188405bfded45d2b7d0259c204611064d3bb4da5364ed70ce1b33e0f70fff"
}

rule MalwareBazaar_unknown_025_098a8592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "098a85921ef63f6076c18316d8437759f7c143794f4f4bf53901db1a12fac728"
    family = "unknown"
    file_name = "mbupload-zhpskrdh.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:41:48"
  condition:
    hash.sha256(0, filesize) == "098a85921ef63f6076c18316d8437759f7c143794f4f4bf53901db1a12fac728"
}

rule MalwareBazaar_unknown_026_519c0a65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "519c0a6541692082d0b71d12bd582128b20c8fe9541be676ee2ebe389943830a"
    family = "unknown"
    file_name = "mbupload-xc0atw_0.bin"
    file_type = "sh"
    first_seen = "2026-10-01 04:41:42"
  condition:
    hash.sha256(0, filesize) == "519c0a6541692082d0b71d12bd582128b20c8fe9541be676ee2ebe389943830a"
}

rule MalwareBazaar_unknown_027_256fff3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "256fff3dae1bb819c8b21fdc807795c3301354797ed8714b363e532c8602a94e"
    family = "unknown"
    file_name = "mbupload-nobkugyv.bin"
    file_type = "dll"
    first_seen = "2026-10-01 04:41:37"
  condition:
    hash.sha256(0, filesize) == "256fff3dae1bb819c8b21fdc807795c3301354797ed8714b363e532c8602a94e"
}

rule MalwareBazaar_WannaCry_028_22618abc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22618abc5d61041a92b4ba1b15742f09d8d43630df249395b5d7c4df8a1112aa"
    family = "WannaCry"
    file_name = "mbupload-tl8tzsiz.bin"
    file_type = "dll"
    first_seen = "2026-10-01 04:41:31"
  condition:
    hash.sha256(0, filesize) == "22618abc5d61041a92b4ba1b15742f09d8d43630df249395b5d7c4df8a1112aa"
}

rule MalwareBazaar_WannaCry_029_1e4b319e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e4b319e9aaa514af9a0ca9b31bae004b8d5a77e9a6aa5edcd957025872710ba"
    family = "WannaCry"
    file_name = "mbupload-vq31wrg6.bin"
    file_type = "dll"
    first_seen = "2026-10-01 04:41:23"
  condition:
    hash.sha256(0, filesize) == "1e4b319e9aaa514af9a0ca9b31bae004b8d5a77e9a6aa5edcd957025872710ba"
}

rule MalwareBazaar_DDoSAgent_030_035a6840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "035a6840a15e6dcea0403627bb22f749e3aba785da74c839400d5209cccd5292"
    family = "DDoSAgent"
    file_name = "mbupload-7381a5bi.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:41:16"
  condition:
    hash.sha256(0, filesize) == "035a6840a15e6dcea0403627bb22f749e3aba785da74c839400d5209cccd5292"
}

rule MalwareBazaar_DDoSAgent_031_6b844ca3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b844ca37d2f209a0136c4c337bdaeba4afc6c454b44dc351c248ceaae7fc135"
    family = "DDoSAgent"
    file_name = "mbupload-zk08aeq1.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:41:07"
  condition:
    hash.sha256(0, filesize) == "6b844ca37d2f209a0136c4c337bdaeba4afc6c454b44dc351c248ceaae7fc135"
}

rule MalwareBazaar_SnakeBiteAgent_032_ca13d65a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca13d65a37a6a7475a57fa4edb457f4059ba3cea9056d8a0c29bfa7db48ed108"
    family = "SnakeBiteAgent"
    file_name = "Supply List_Purchase Order.zip"
    file_type = "zip"
    first_seen = "2026-10-01 04:41:05"
  condition:
    hash.sha256(0, filesize) == "ca13d65a37a6a7475a57fa4edb457f4059ba3cea9056d8a0c29bfa7db48ed108"
}

rule MalwareBazaar_Mirai_033_40bce4fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40bce4fc2d48b01e29c714cd2478fb34d94688ba123a24ab69976599110939be"
    family = "Mirai"
    file_name = "mbupload-4w4u3h99.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:40:59"
  condition:
    hash.sha256(0, filesize) == "40bce4fc2d48b01e29c714cd2478fb34d94688ba123a24ab69976599110939be"
}

rule MalwareBazaar_Mirai_034_3637ebd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3637ebd9a53af109fd1ce055f074563d9749d099fb49e622023d5d01e3641168"
    family = "Mirai"
    file_name = "mbupload-nzlbtikh.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:40:53"
  condition:
    hash.sha256(0, filesize) == "3637ebd9a53af109fd1ce055f074563d9749d099fb49e622023d5d01e3641168"
}

rule MalwareBazaar_Mirai_035_b94bb5e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94bb5e3dc898727f3e411fe174438450ccece7a4f801a5e0eb76a15c7db914c"
    family = "Mirai"
    file_name = "mbupload-d1n6by16.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:40:45"
  condition:
    hash.sha256(0, filesize) == "b94bb5e3dc898727f3e411fe174438450ccece7a4f801a5e0eb76a15c7db914c"
}

rule MalwareBazaar_unknown_036_4610ccf1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f"
    family = "unknown"
    file_name = "4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f.bin"
    file_type = "zip"
    first_seen = "2026-10-01 04:28:49"
  condition:
    hash.sha256(0, filesize) == "4610ccf1547c2cb490b43b31bd9f6f79913e3339b4d6cb05db1a60eb04b2813f"
}

rule MalwareBazaar_Mirai_037_11b606a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11b606a4c098c99a6fae1c6c56fa09590616fe503639308b5e773c83df85b94e"
    family = "Mirai"
    file_name = "fa6f34f439e2f40f.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:25:24"
  condition:
    hash.sha256(0, filesize) == "11b606a4c098c99a6fae1c6c56fa09590616fe503639308b5e773c83df85b94e"
}

rule MalwareBazaar_Mirai_038_fa6f34f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa6f34f439e2f40fcdccaa83a88e08fbe2e9285eba8c9e29228df3e3c16c1078"
    family = "Mirai"
    file_name = "fa6f34f439e2f40f.bin"
    file_type = "elf"
    first_seen = "2026-10-01 04:24:44"
  condition:
    hash.sha256(0, filesize) == "fa6f34f439e2f40fcdccaa83a88e08fbe2e9285eba8c9e29228df3e3c16c1078"
}

rule MalwareBazaar_unknown_039_1beabccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e"
    family = "unknown"
    file_name = "1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:18:37"
  condition:
    hash.sha256(0, filesize) == "1beabccc2954aceebc2e51ad36b0f704add1b50081526717a3535115a7da980e"
}

rule MalwareBazaar_Mirai_040_db11b9ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6"
    family = "Mirai"
    file_name = "db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6"
    file_type = "elf"
    first_seen = "2026-10-01 04:17:14"
  condition:
    hash.sha256(0, filesize) == "db11b9baed28a20871bf74a1126b1f202d974da51f865b2a6e3eccb1b0f9e4b6"
}

rule MalwareBazaar_CoinMiner_041_1e3bc11e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666"
    family = "CoinMiner"
    file_name = "1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:13:37"
  condition:
    hash.sha256(0, filesize) == "1e3bc11e2a8404619ca6b092555233fb41b889a88900ff50e440e9b9d6782666"
}

rule MalwareBazaar_ConnectWise_042_5adc928c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8"
    family = "ConnectWise"
    file_name = "5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:13:15"
  condition:
    hash.sha256(0, filesize) == "5adc928c90571c9c956ed1b869b3acb87133ee1a1e63e61aa8324f7c1cc037f8"
}

rule MalwareBazaar_unknown_043_145e01a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "145e01a971611cdb401e8122899478a3c071f308e695726306baedf191b9fd7e"
    family = "unknown"
    file_name = "reg.exe"
    file_type = "exe"
    first_seen = "2026-10-01 04:11:56"
  condition:
    hash.sha256(0, filesize) == "145e01a971611cdb401e8122899478a3c071f308e695726306baedf191b9fd7e"
}

rule MalwareBazaar_Formbook_044_786169a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "786169a79bb505773566b041070dee3bb1c6ea67385acfc63ecf989ce701c87a"
    family = "Formbook"
    file_name = "mv TOI CHALLENGER SHIP INFORMATION.com"
    file_type = "exe"
    first_seen = "2026-10-01 04:06:20"
  condition:
    hash.sha256(0, filesize) == "786169a79bb505773566b041070dee3bb1c6ea67385acfc63ecf989ce701c87a"
}

rule MalwareBazaar_AgentTesla_045_e76c5c79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76c5c79066d31f5e84b172d61ba575926a18505efa47a9d9a0c7c1c0ced4768"
    family = "AgentTesla"
    file_name = "Shipment_Invoice_and_Packing_List.com"
    file_type = "exe"
    first_seen = "2026-10-01 04:03:48"
  condition:
    hash.sha256(0, filesize) == "e76c5c79066d31f5e84b172d61ba575926a18505efa47a9d9a0c7c1c0ced4768"
}

rule MalwareBazaar_unknown_046_84d68a89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d68a89a5f07f096cca74e9c96869490056e8b911fd84cd73e5744bed1a7022"
    family = "unknown"
    file_name = "InitialPayload.jar"
    file_type = "jar"
    first_seen = "2026-10-01 03:58:16"
  condition:
    hash.sha256(0, filesize) == "84d68a89a5f07f096cca74e9c96869490056e8b911fd84cd73e5744bed1a7022"
}

rule MalwareBazaar_GCleaner_047_7b254af9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1"
    family = "GCleaner"
    file_name = "7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:42:49"
  condition:
    hash.sha256(0, filesize) == "7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1"
}

rule MalwareBazaar_Mirai_048_87568fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87568fa4215f1e230bf15f9bdb88528b7ad5d58e9ffb51324dc37c6ecfa00e99"
    family = "Mirai"
    file_name = "mbupload-152sjsqs.bin"
    file_type = "elf"
    first_seen = "2026-10-01 03:39:49"
  condition:
    hash.sha256(0, filesize) == "87568fa4215f1e230bf15f9bdb88528b7ad5d58e9ffb51324dc37c6ecfa00e99"
}

rule MalwareBazaar_unknown_049_5fef2449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81"
    family = "unknown"
    file_name = "5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81.bin"
    file_type = "apk"
    first_seen = "2026-10-01 03:32:47"
  condition:
    hash.sha256(0, filesize) == "5fef2449ce26f0820e72a42ee45f578ce14cef908c52063cd595b000d4665a81"
}

rule MalwareBazaar_unknown_050_2a6f2f27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4"
    family = "unknown"
    file_name = "2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4.bin"
    file_type = "apk"
    first_seen = "2026-10-01 03:28:44"
  condition:
    hash.sha256(0, filesize) == "2a6f2f273af0d9b0675c466f01bc6d81245df7105bdae8d25b9bbfabfa3f19c4"
}

rule MalwareBazaar_VShell_051_b25ead9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21"
    family = "VShell"
    file_name = "b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:28:35"
  condition:
    hash.sha256(0, filesize) == "b25ead9ba12a34db6d355d52790964c533168859affbfacf36cd735f63a1dd21"
}

rule MalwareBazaar_VShell_052_635f0f9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e"
    family = "VShell"
    file_name = "635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:27:47"
  condition:
    hash.sha256(0, filesize) == "635f0f9aed2508d4cbb776450716b3671cd78870fceee8d0dcec8680e05d9b6e"
}

rule MalwareBazaar_unknown_053_629d2985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1"
    family = "unknown"
    file_name = "629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1.bin"
    file_type = "zip"
    first_seen = "2026-10-01 03:18:28"
  condition:
    hash.sha256(0, filesize) == "629d2985c6173cb498b7c7233b551bd3bd2725270d34fad424cd30a324fe73f1"
}

rule MalwareBazaar_unknown_054_63c9b46c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221"
    family = "unknown"
    file_name = "63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221.bin"
    file_type = "zip"
    first_seen = "2026-10-01 03:17:47"
  condition:
    hash.sha256(0, filesize) == "63c9b46cfaa62abf69df2713c55e0e67a7bd524f77788aafa0b0b8ad359f0221"
}

rule MalwareBazaar_Mirai_055_2f03d283
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65"
    family = "Mirai"
    file_name = "2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65"
    file_type = "elf"
    first_seen = "2026-10-01 03:17:15"
  condition:
    hash.sha256(0, filesize) == "2f03d283a5302a745f357129b5ec45ea27b84e5adf72c6e87092fe7dbbb23c65"
}

rule MalwareBazaar_unknown_056_8570d8ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0"
    family = "unknown"
    file_name = "8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0.bin"
    file_type = "zip"
    first_seen = "2026-10-01 03:13:49"
  condition:
    hash.sha256(0, filesize) == "8570d8ec3fdb34495f6824ea39f48eb5c7f71a2c3815b43456fe8ac706c61ad0"
}

rule MalwareBazaar_unknown_057_e598af51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e"
    family = "unknown"
    file_name = "e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e.exe"
    file_type = "exe"
    first_seen = "2026-10-01 03:12:54"
  condition:
    hash.sha256(0, filesize) == "e598af514da17a32559282bf68e199821b0a393941a7d2215a83e75c55f9227e"
}

rule MalwareBazaar_DattoRMM_058_279059e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f"
    family = "DattoRMM"
    file_name = "279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:58:22"
  condition:
    hash.sha256(0, filesize) == "279059e4ec630097dbc1a2e3e7a065638acbbcaf8743247fba8924b762875a2f"
}

rule MalwareBazaar_Mirai_059_9350cc4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343"
    family = "Mirai"
    file_name = "9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343.elf"
    file_type = "elf"
    first_seen = "2026-10-01 02:57:52"
  condition:
    hash.sha256(0, filesize) == "9350cc4d7e1b7fd89aa253586bb7a197a700f47e403d8abbc32775c1e4064343"
}

rule MalwareBazaar_unknown_060_116eeece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "116eeeceb2de4e549b94a81009755e745ced15b6189bc2ffa1574550307b8245"
    family = "unknown"
    file_name = "4c7d6f187d17322c675cbaeb248c7dc5"
    file_type = "dll"
    first_seen = "2026-10-01 02:50:35"
  condition:
    hash.sha256(0, filesize) == "116eeeceb2de4e549b94a81009755e745ced15b6189bc2ffa1574550307b8245"
}

rule MalwareBazaar_Heodo_061_07adbb53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9"
    family = "Heodo"
    file_name = "07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9.msi"
    file_type = "msi"
    first_seen = "2026-10-01 02:47:58"
  condition:
    hash.sha256(0, filesize) == "07adbb53e9cfea58b919fded0bf6e895b26b1d1eb78fd2a162b8d313008176e9"
}

rule MalwareBazaar_VShell_062_53cc143c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7"
    family = "VShell"
    file_name = "53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:47:47"
  condition:
    hash.sha256(0, filesize) == "53cc143c730ee92dba972b6c414f4499996bb6864ee300ec0da657b654d63df7"
}

rule MalwareBazaar_unknown_063_b45e3b14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c"
    family = "unknown"
    file_name = "b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:39:20"
  condition:
    hash.sha256(0, filesize) == "b45e3b14e530db32de40e0352f10e19715986de727fa5b0caa74f00a3e35a93c"
}

rule MalwareBazaar_unknown_064_4e1d821d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50"
    family = "unknown"
    file_name = "4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:38:37"
  condition:
    hash.sha256(0, filesize) == "4e1d821d4df8a1bc9201943733e4d635bd695329d8ee7b63071ec8a26b208c50"
}

rule MalwareBazaar_VShell_065_4ecc8733
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64"
    family = "VShell"
    file_name = "4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:37:56"
  condition:
    hash.sha256(0, filesize) == "4ecc8733de929518963f77d054d8fb88caf2fda5ac7ddf7d9b450c269ae5ba64"
}

rule MalwareBazaar_VShell_066_5fb5bf9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23"
    family = "VShell"
    file_name = "5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:37:53"
  condition:
    hash.sha256(0, filesize) == "5fb5bf9ffb35f89ccb1a615a45d578ea5d0c7e11ed3df5dd259eb523fd43cf23"
}

rule MalwareBazaar_VShell_067_e136fd44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9"
    family = "VShell"
    file_name = "e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9.exe"
    file_type = "exe"
    first_seen = "2026-10-01 02:37:47"
  condition:
    hash.sha256(0, filesize) == "e136fd4421febdf5ac2d8266cba0670708f0b53a1b09f672e7a1c71f1eba19e9"
}

rule MalwareBazaar_unknown_068_df5ca188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2"
    family = "unknown"
    file_name = "df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2.bin"
    file_type = "ps1"
    first_seen = "2026-10-01 02:27:50"
  condition:
    hash.sha256(0, filesize) == "df5ca1884dc8dd8514902293e21def2724b2d069c0bbce387747d843c4acd0c2"
}

rule MalwareBazaar_Formbook_069_3bb89c9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bb89c9e7eff35cd476e57b77412497cacd3833cf8d7f7139f6671a1284ac16c"
    family = "Formbook"
    file_name = "Q88_Manas_2026.01.10.com"
    file_type = "exe"
    first_seen = "2026-10-01 02:26:31"
  condition:
    hash.sha256(0, filesize) == "3bb89c9e7eff35cd476e57b77412497cacd3833cf8d7f7139f6671a1284ac16c"
}

rule MalwareBazaar_AsyncRAT_070_935f2d6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935f2d6a19b549430c702863aa0f563c42b0dbaca4cde8d6903e70843858dcf5"
    family = "AsyncRAT"
    file_name = "POs 2701789 & 2701790.JS.js"
    file_type = "js"
    first_seen = "2026-10-01 02:25:05"
  condition:
    hash.sha256(0, filesize) == "935f2d6a19b549430c702863aa0f563c42b0dbaca4cde8d6903e70843858dcf5"
}

rule MalwareBazaar_Mirai_071_b02d58f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62"
    family = "Mirai"
    file_name = "b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62"
    file_type = "elf"
    first_seen = "2026-10-01 02:17:14"
  condition:
    hash.sha256(0, filesize) == "b02d58f230484452750855a20d734d6c9b3540290b0c8162493312c53bdf3c62"
}

rule MalwareBazaar_unknown_072_72ea940b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72ea940b351560c210c6c8a89171e43b932c99089985b7fcc85f58a8910eb2c6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-01 02:15:03"
  condition:
    hash.sha256(0, filesize) == "72ea940b351560c210c6c8a89171e43b932c99089985b7fcc85f58a8910eb2c6"
}

rule MalwareBazaar_Mirai_073_07146515
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0714651541a17ca4cd54ccc018d23b02aaf248d9d7ea5e6dab507ecef3c8e699"
    family = "Mirai"
    file_name = "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
    file_type = "elf"
    first_seen = "2026-10-01 01:29:20"
  condition:
    hash.sha256(0, filesize) == "0714651541a17ca4cd54ccc018d23b02aaf248d9d7ea5e6dab507ecef3c8e699"
}

rule MalwareBazaar_Mirai_074_f5d5e071
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
    family = "Mirai"
    file_name = "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
    file_type = "elf"
    first_seen = "2026-10-01 01:28:17"
  condition:
    hash.sha256(0, filesize) == "f5d5e0711b83f267212214ae75320021d75e18e7286cda9b91638d945054f1f6"
}

rule MalwareBazaar_CoinMiner_075_0105b852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475"
    family = "CoinMiner"
    file_name = "0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475"
    file_type = "gz"
    first_seen = "2026-10-01 01:25:13"
  condition:
    hash.sha256(0, filesize) == "0105b8528e478ccf1bee1d5bcb5c2cd814efa95664b6f4b12dd8a6df37f63475"
}

rule MalwareBazaar_Mirai_076_cd192065
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1920655fb815cd6fd2ef89229a2624c3ed389da33ed33efcb8da3c654455e6"
    family = "Mirai"
    file_name = "cd1920655fb815cd.bin"
    file_type = "elf"
    first_seen = "2026-10-01 01:25:08"
  condition:
    hash.sha256(0, filesize) == "cd1920655fb815cd6fd2ef89229a2624c3ed389da33ed33efcb8da3c654455e6"
}

rule MalwareBazaar_RemcosRAT_077_212f8f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "212f8f40b7451d925ef733cdd8d565d0070082b17f08cee182e150ee42d4783c"
    family = "RemcosRAT"
    file_name = "CONTRACT DRAFT-EGP-25006-SG1-SLO-GS-0349.vbs"
    file_type = "vbs"
    first_seen = "2026-10-01 01:22:56"
  condition:
    hash.sha256(0, filesize) == "212f8f40b7451d925ef733cdd8d565d0070082b17f08cee182e150ee42d4783c"
}

rule MalwareBazaar_unknown_078_3465860b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89"
    family = "unknown"
    file_name = "3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89.exe"
    file_type = "exe"
    first_seen = "2026-10-01 01:17:48"
  condition:
    hash.sha256(0, filesize) == "3465860b2626b93d795d8b0a53af173d260e538ebb345163076e7e79c70b9e89"
}

rule MalwareBazaar_Mirai_079_1d214f5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6"
    family = "Mirai"
    file_name = "1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6"
    file_type = "elf"
    first_seen = "2026-10-01 01:17:13"
  condition:
    hash.sha256(0, filesize) == "1d214f5c9a401e6c1efe00dac4c127d9da8494b1038cd1d0b2a3a82bda01a3b6"
}

rule MalwareBazaar_RemcosRAT_080_13045b38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13045b384561af13da3cbea5be0440e1939e3765b66fbd43a4f64990f60f072c"
    family = "RemcosRAT"
    file_name = "Final rooming list.js"
    file_type = "js"
    first_seen = "2026-10-01 01:05:07"
  condition:
    hash.sha256(0, filesize) == "13045b384561af13da3cbea5be0440e1939e3765b66fbd43a4f64990f60f072c"
}

rule MalwareBazaar_unknown_081_46a085ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46a085ef0b76c648832a1e3dfe0cf0a06cd1af5d63cc23095e32e9dabf53e635"
    family = "unknown"
    file_name = "macho_46a085ef0b76.bin"
    file_type = "macho"
    first_seen = "2026-10-01 00:54:34"
  condition:
    hash.sha256(0, filesize) == "46a085ef0b76c648832a1e3dfe0cf0a06cd1af5d63cc23095e32e9dabf53e635"
}

rule MalwareBazaar_GCleaner_082_53a6c8ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53a6c8ee1cff71c0178eea23371d14a7ab9aa3244307c24d3e2197ede129e9a4"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-10-01 00:52:07"
  condition:
    hash.sha256(0, filesize) == "53a6c8ee1cff71c0178eea23371d14a7ab9aa3244307c24d3e2197ede129e9a4"
}

rule MalwareBazaar_Mirai_083_29fa6a78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29fa6a78fe8371844fc5e4492fe9368021e562ba0d413729204c17951491e7a1"
    family = "Mirai"
    file_name = "0dddc309b0d30ccc.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:26:19"
  condition:
    hash.sha256(0, filesize) == "29fa6a78fe8371844fc5e4492fe9368021e562ba0d413729204c17951491e7a1"
}

rule MalwareBazaar_Mirai_084_6a3a79fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a3a79fb869e2ea322090841822ceae3725de2441546e45cdabe82ef763d7cd7"
    family = "Mirai"
    file_name = "6a3a79fb869e2ea3.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:57"
  condition:
    hash.sha256(0, filesize) == "6a3a79fb869e2ea322090841822ceae3725de2441546e45cdabe82ef763d7cd7"
}

rule MalwareBazaar_Mirai_085_0dddc309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dddc309b0d30ccc26cc52c0dbda60ea3e447c07a9261c561c0cfe40ebc2f928"
    family = "Mirai"
    file_name = "0dddc309b0d30ccc.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:47"
  condition:
    hash.sha256(0, filesize) == "0dddc309b0d30ccc26cc52c0dbda60ea3e447c07a9261c561c0cfe40ebc2f928"
}

rule MalwareBazaar_Mirai_086_e8d544cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8d544cbeeef8a4d687a24cba5e390dc0a3a9027e2e78507f0ee8b4c4a8e9b86"
    family = "Mirai"
    file_name = "e8d544cbeeef8a4d.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:40"
  condition:
    hash.sha256(0, filesize) == "e8d544cbeeef8a4d687a24cba5e390dc0a3a9027e2e78507f0ee8b4c4a8e9b86"
}

rule MalwareBazaar_Mirai_087_08116fa6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08116fa61c263e41459257c950fdda70113a3c7474060f71db98b10e0c5339a0"
    family = "Mirai"
    file_name = "08116fa61c263e41.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:32"
  condition:
    hash.sha256(0, filesize) == "08116fa61c263e41459257c950fdda70113a3c7474060f71db98b10e0c5339a0"
}

rule MalwareBazaar_Mirai_088_c8f51f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8f51f05a57025aeae8514642f4cbb134b3c4ce713488cf87c3a4855820e5694"
    family = "Mirai"
    file_name = "c8f51f05a57025ae.bin"
    file_type = "elf"
    first_seen = "2026-10-01 00:25:24"
  condition:
    hash.sha256(0, filesize) == "c8f51f05a57025aeae8514642f4cbb134b3c4ce713488cf87c3a4855820e5694"
}

rule MalwareBazaar_unknown_089_1c875667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e"
    family = "unknown"
    file_name = "1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e"
    file_type = "elf"
    first_seen = "2026-10-01 00:18:00"
  condition:
    hash.sha256(0, filesize) == "1c875667079fabc7427cabf90759968aa0567abd7b086e569be94658b5542a3e"
}

rule MalwareBazaar_Mirai_090_f83a0266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33"
    family = "Mirai"
    file_name = "f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33"
    file_type = "elf"
    first_seen = "2026-10-01 00:17:54"
  condition:
    hash.sha256(0, filesize) == "f83a026679ba4125c55774943fc76c1592170999ec6ea80f5c9127d77c3d6e33"
}

rule MalwareBazaar_unknown_091_45db5310
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45db5310a177214d3a38ce54e6a3abd9da05ba456f925886cdab810b396dc528"
    family = "unknown"
    file_name = "update.apk"
    file_type = "apk"
    first_seen = "2026-10-01 00:09:07"
  condition:
    hash.sha256(0, filesize) == "45db5310a177214d3a38ce54e6a3abd9da05ba456f925886cdab810b396dc528"
}

rule MalwareBazaar_unknown_092_3a5e7a1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a5e7a1e5d4394d3a4fce80595dfc03301d3d6cce55094bd34a2de7b1c2c814c"
    family = "unknown"
    file_name = "macho_3a5e7a1e5d43.bin"
    file_type = "macho"
    first_seen = "2026-09-30 23:44:44"
  condition:
    hash.sha256(0, filesize) == "3a5e7a1e5d4394d3a4fce80595dfc03301d3d6cce55094bd34a2de7b1c2c814c"
}

rule MalwareBazaar_Mirai_093_474348c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1"
    family = "Mirai"
    file_name = "474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1"
    file_type = "elf"
    first_seen = "2026-09-30 23:17:13"
  condition:
    hash.sha256(0, filesize) == "474348c456e836f0076bd6cbcef672d6c9418ec26276ecb50ee9a877f91447c1"
}

rule MalwareBazaar_unknown_094_695d1993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "695d1993072310f65fe068c507235ccd184a4c9a876d6179388778d1490ab39d"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-30 23:14:48"
  condition:
    hash.sha256(0, filesize) == "695d1993072310f65fe068c507235ccd184a4c9a876d6179388778d1490ab39d"
}

rule MalwareBazaar_RemcosRAT_095_c2791fd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2791fd5366675b995d332565998f6fc84bbcca2af6567f8cc21f6aabd8d54b1"
    family = "RemcosRAT"
    file_name = "Complete Set of Documents For Bill of Lading - 238591458.vbs"
    file_type = "vbs"
    first_seen = "2026-09-30 23:13:37"
  condition:
    hash.sha256(0, filesize) == "c2791fd5366675b995d332565998f6fc84bbcca2af6567f8cc21f6aabd8d54b1"
}

rule MalwareBazaar_unknown_096_c3c20785
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d"
    family = "unknown"
    file_name = "c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d.exe"
    file_type = "exe"
    first_seen = "2026-09-30 23:12:07"
  condition:
    hash.sha256(0, filesize) == "c3c207857f29cba45d3affdff3078f1a7c546529c55e9bdf18a5277fa0d6495d"
}

rule MalwareBazaar_unknown_097_1530fceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1530fcebb5e0693234aee367915cf7485c66477b26c5fc70d367bef05b3b1872"
    family = "unknown"
    file_name = "05f3c4c98cf6ebdc972e7d196d0a3ef0"
    file_type = "dll"
    first_seen = "2026-09-30 23:10:44"
  condition:
    hash.sha256(0, filesize) == "1530fcebb5e0693234aee367915cf7485c66477b26c5fc70d367bef05b3b1872"
}

rule MalwareBazaar_Mirai_098_6b98f26a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b98f26a10b2c3c75cfdbd66d983a72785b71fd1ad4f16b7d7e660fcf0f99122"
    family = "Mirai"
    file_name = "loligang.arm7"
    file_type = "elf"
    first_seen = "2026-09-30 22:50:58"
  condition:
    hash.sha256(0, filesize) == "6b98f26a10b2c3c75cfdbd66d983a72785b71fd1ad4f16b7d7e660fcf0f99122"
}

rule MalwareBazaar_Mirai_099_f2399176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f23991766ddae548a8d22c65c1741b62d349f22506d2293a9e39bc9aa8e188c9"
    family = "Mirai"
    file_name = "loligang.arm6"
    file_type = "elf"
    first_seen = "2026-09-30 22:44:54"
  condition:
    hash.sha256(0, filesize) == "f23991766ddae548a8d22c65c1741b62d349f22506d2293a9e39bc9aa8e188c9"
}

rule MalwareBazaar_unknown_100_8ae3ecc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ae3ecc64619fb0ebee9bd539d757cd22b10595a71d5fb24f33688f93ec664da"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-30 22:43:04"
  condition:
    hash.sha256(0, filesize) == "8ae3ecc64619fb0ebee9bd539d757cd22b10595a71d5fb24f33688f93ec664da"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

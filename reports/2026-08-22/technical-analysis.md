# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-22

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 643 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 643 |
| Unique family labels | 9 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 42 |
| Mirai | 23 |
| RemusStealer | 22 |
| ValleyRAT | 7 |
| SnappyClient | 2 |
| NeedleStealer | 1 |
| Socks5Systemz | 1 |
| DCRat | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 46 |
| elf | 24 |
| unknown | 13 |
| sh | 9 |
| dll | 6 |
| js | 1 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `bb1a0a0ca087de0e`

| Field | Value |
|---|---|
| SHA-256 | `bb1a0a0ca087de0e231f567453d5652fa2af5819412ee602e0ffd601f1a186ec` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 01:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1489263138762a074e29514386dd9e2b` |
| SHA-256 | `bb1a0a0ca087de0e231f567453d5652fa2af5819412ee602e0ffd601f1a186ec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_bb1a0a0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb1a0a0ca087de0e231f567453d5652fa2af5819412ee602e0ffd601f1a186ec"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 01:52:11"
  condition:
    hash.sha256(0, filesize) == "bb1a0a0ca087de0e231f567453d5652fa2af5819412ee602e0ffd601f1a186ec"
}
```

### Sample 2: `8c848798aab18991`

| Field | Value |
|---|---|
| SHA-256 | `8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f` |
| Family label | `Mirai` |
| File name | `8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f.elf` |
| File type | `elf` |
| First seen | `2026-08-22 01:51:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b110d60e658b58f29f911ad12e1281cc` |
| SHA-1 | `83d42e4248b89eeab18dd0a0834609f5479c4e15` |
| SHA-256 | `8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f` |
| SHA3-384 | `ccef07577b8d27b6f3ccf0559b8b434e59fa3b74a6926ce4701a0af3f772c2b60115d587180e7d21898790edc1d462d1` |
| TLSH | `T189634A03298050FDC8D9D5B8169F6236D923F57D2376B31A33D0FA197EADE213B6A604` |
| TELFHASH | `t1bb216871386a0590e0d7e1b2b346e2795d341b2110e676f2eab2b4f7cb11b8216f6833` |
| SSDEEP | `1536:m3hEFPUli8uSGB8Cn91VnGYPEKnOWTyCJ/AF:mxyQiPSG3n9zGblWTyCJi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_8c848798
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f"
    family = "Mirai"
    file_name = "8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 01:51:03"
  condition:
    hash.sha256(0, filesize) == "8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f"
}
```

### Sample 3: `49b81f37896cb76b`

| Field | Value |
|---|---|
| SHA-256 | `49b81f37896cb76b7a2b54a1bdac64caeb1513abf26ddc8da5f9e24f9ab74390` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:49:44` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09c991e1f56af909d17f19f0ebef6965` |
| SHA-1 | `0cb6feec9a866cd70ccf980545482fea2bc1ab50` |
| SHA-256 | `49b81f37896cb76b7a2b54a1bdac64caeb1513abf26ddc8da5f9e24f9ab74390` |
| SHA3-384 | `d7d85368ac2cbd40116057fab946bc7cfbc5a11ddcdcb0ddf94ee03b302f92b96e8933a8d3fae27bb450fd161a1b5585` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T12DF63316979070EDF152D4B88889C741F735BC8AAB70CAD7179CFAAB2F52590EA0C335` |
| SSDEEP | `393216:sDbpWrHctdOoDVQkCwd41bqtK979Gvmi/G0H7g3B:svpWrSE4a1bx9JWH7cB` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_49b81f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49b81f37896cb76b7a2b54a1bdac64caeb1513abf26ddc8da5f9e24f9ab74390"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:49:44"
  condition:
    hash.sha256(0, filesize) == "49b81f37896cb76b7a2b54a1bdac64caeb1513abf26ddc8da5f9e24f9ab74390"
}
```

### Sample 4: `303555a2115d8510`

| Field | Value |
|---|---|
| SHA-256 | `303555a2115d8510f7f8e663e3c25a3310000c3a20950089633902c6245f7cc3` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:48:53` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68cd9101ae8329762157dcc0e138ef6f` |
| SHA-1 | `4455a662d79d270c8b52d88c90b6465269ac3ccc` |
| SHA-256 | `303555a2115d8510f7f8e663e3c25a3310000c3a20950089633902c6245f7cc3` |
| SHA3-384 | `f1c602e5176c711060ac96dfc3fc4710e8ba346c41784e3a624e6183f60bb01f405a83ba0d02696d3eeed26b56b6e538` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T15C362307E7A420FDF066D9308946DB00F7313C496B71EAAB17E8E95B2F62190D92D736` |
| SSDEEP | `98304:rKAUxUZKdU9xEhFQw9gLuJvCK7PDCdMnpRHO7UuHBpZ2KNU:r8xbU96jQw9+pKj+kpE7UuH12KNU` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_303555a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "303555a2115d8510f7f8e663e3c25a3310000c3a20950089633902c6245f7cc3"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:48:53"
  condition:
    hash.sha256(0, filesize) == "303555a2115d8510f7f8e663e3c25a3310000c3a20950089633902c6245f7cc3"
}
```

### Sample 5: `6d70fb7ee01bcca8`

| Field | Value |
|---|---|
| SHA-256 | `6d70fb7ee01bcca86fde4aa7154ae198eeacf9dbc852c824fe2317397ce1f1de` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:47:51` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c4df3c3fa1eebd090d3fdaf90414840` |
| SHA-1 | `3de72121436ca2bf56cccfa846b27837b9b97932` |
| SHA-256 | `6d70fb7ee01bcca86fde4aa7154ae198eeacf9dbc852c824fe2317397ce1f1de` |
| SHA3-384 | `cf0033e52b4ec32f6f19391b7f9e18c7ddad63a59b73b09207dff331ef1c253a51a03e47f77b8566cafe57abe01762d5` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T116F63306A3A468EDF022E8394507D701FB317C45A631EA9B17ECFA1B2F52491E93DB35` |
| SSDEEP | `393216:gaASkVuaQ7mR5iozLDsugBICr9JlRnofzngH60:gljVwqiPrTPofzep` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_6d70fb7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d70fb7ee01bcca86fde4aa7154ae198eeacf9dbc852c824fe2317397ce1f1de"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:47:51"
  condition:
    hash.sha256(0, filesize) == "6d70fb7ee01bcca86fde4aa7154ae198eeacf9dbc852c824fe2317397ce1f1de"
}
```

### Sample 6: `799a7ba7f0e68529`

| Field | Value |
|---|---|
| SHA-256 | `799a7ba7f0e68529c61e4cb73bd8a1e57d5648786937335e36e53ed1ab56a932` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:46:56` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `470c5b26720a738c2b3b686ed2567fa5` |
| SHA-1 | `71ccd7117fcd5fb491339a202d769c54213c94d3` |
| SHA-256 | `799a7ba7f0e68529c61e4cb73bd8a1e57d5648786937335e36e53ed1ab56a932` |
| SHA3-384 | `2739c81c4043ab2ba82dff84e2ef2f15ad12d263caa98eb9f5549971d389a783a242ad37aa22cbff65f60c2a6097db57` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T128F63301EB40306AFC76D678CFF7C7B0DA217C4A076196DA07E4696B1EB71D1CA26722` |
| SSDEEP | `393216:UxkJQ3EjS8t7CDjXLtTXcqmu8pL6y9edR7PeIHEydRSxbMJ:U2mZ8oNcqmuKef7PbbdvJ` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_799a7ba7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "799a7ba7f0e68529c61e4cb73bd8a1e57d5648786937335e36e53ed1ab56a932"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:46:56"
  condition:
    hash.sha256(0, filesize) == "799a7ba7f0e68529c61e4cb73bd8a1e57d5648786937335e36e53ed1ab56a932"
}
```

### Sample 7: `57713a4f584665cb`

| Field | Value |
|---|---|
| SHA-256 | `57713a4f584665cbb42ecddd749459c10c7a369e3b1beaaabd4d694891e16933` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:46:02` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b40366aadc86b16f62ae3b6e25c3ca65` |
| SHA-1 | `9b463b9c5967a4b1204aaa04d0637cc946359d95` |
| SHA-256 | `57713a4f584665cbb42ecddd749459c10c7a369e3b1beaaabd4d694891e16933` |
| SHA3-384 | `e3048a56fccf7d38e1df60a6c912e4e3cfb0d8722259424a4095536cab49728b9c9216538d9cf18d1134231d08a0f80a` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1B9F63301EBA4716AFCA6DA3CCEB3CAD0E935BC46072552EB27D8545F1EB71D1C62A301` |
| SSDEEP | `393216:mvt/rZuc0fo/TaMoXTaaqGaWuEmpkvCOc7yZYY7XyrlroqJ:m1zcdA/TaMiaaqLJppD+CAyrlrtJ` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_57713a4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57713a4f584665cbb42ecddd749459c10c7a369e3b1beaaabd4d694891e16933"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:46:02"
  condition:
    hash.sha256(0, filesize) == "57713a4f584665cbb42ecddd749459c10c7a369e3b1beaaabd4d694891e16933"
}
```

### Sample 8: `2779033e8c0bd3d1`

| Field | Value |
|---|---|
| SHA-256 | `2779033e8c0bd3d1c2332d1a4c498b09d2eb090fff10a5aad7adbfb3a5231d72` |
| Family label | `ValleyRAT` |
| File name | `FCFA826B899EE297DF49F4EF756857D2.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:45:24` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcfa826b899ee297df49f4ef756857d2` |
| SHA-1 | `f80f02bb9a6f79f3a23fc44804976331e12631da` |
| SHA-256 | `2779033e8c0bd3d1c2332d1a4c498b09d2eb090fff10a5aad7adbfb3a5231d72` |
| SHA3-384 | `f022b2b8ced148c436dce9e8e9df141f2d21b05f5eb0ccd30448ddb2b791957b07e94c21ffeb6c6b34d20e0169d988b2` |
| IMPHASH | `1ff847646487d56f85778df99ff3728a` |
| TLSH | `T18BB7D0C2B182D0B3CB9291F5861EF6BB85FABD15C71C82C392547E916430FE2DA7B146` |
| SSDEEP | `786432:YpFt6oW2p5VLPWNcuIlpf3SFfvK9uk+gP71ymaiq3xKASLqEh7jmrMwP5t:0kodZPsPIlpfis9B++xFaBwqZ` |
| ICON-DHASH | `f0f0ccd4f4d4d4f0` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_008_2779033e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2779033e8c0bd3d1c2332d1a4c498b09d2eb090fff10a5aad7adbfb3a5231d72"
    family = "ValleyRAT"
    file_name = "FCFA826B899EE297DF49F4EF756857D2.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:45:24"
  condition:
    hash.sha256(0, filesize) == "2779033e8c0bd3d1c2332d1a4c498b09d2eb090fff10a5aad7adbfb3a5231d72"
}
```

### Sample 9: `2b435e783dd02a96`

| Field | Value |
|---|---|
| SHA-256 | `2b435e783dd02a969e3ebbef2e88898faa654e72fe48bca19d8328eed051b6ed` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:45:02` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b9f15072c31dd119ff9dae2bd21a084` |
| SHA-1 | `1c731ac38f884ff4e28faf3db19662ed346e1a60` |
| SHA-256 | `2b435e783dd02a969e3ebbef2e88898faa654e72fe48bca19d8328eed051b6ed` |
| SHA3-384 | `a65b63b37deb4d88f0900cb3effd472994d156decb87d837111d5dd16cbda8d22e21882f12bb7553162549483d8291dd` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T13BF63345FBA03969F87753308FB389A2DE313C4A036191EB5790756A1DFB1D4DE2A322` |
| SSDEEP | `196608:rIxbU9Lx0RBLrCgZRfQZGEBzulRP52w5Jg+c/lNoza1jWDO5glNi1jwFfqw4:c+oTf3uyf52w52tro+1QPikl4` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_2b435e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b435e783dd02a969e3ebbef2e88898faa654e72fe48bca19d8328eed051b6ed"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:45:02"
  condition:
    hash.sha256(0, filesize) == "2b435e783dd02a969e3ebbef2e88898faa654e72fe48bca19d8328eed051b6ed"
}
```

### Sample 10: `b3e188bf57cbc7a2`

| Field | Value |
|---|---|
| SHA-256 | `b3e188bf57cbc7a25832ea1623180c43508e31c9dfcd50c914b42954d6dd8ca9` |
| Family label | `unknown` |
| File name | `ae_mixtwo.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:44:02` |
| Reporter | `iamaachum` |
| Tags | `exe, GCleaner, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3887291cd322703465aeb5a65f43eee7` |
| SHA-1 | `bf9592a2d325f2202869f067d54b9375eba1f378` |
| SHA-256 | `b3e188bf57cbc7a25832ea1623180c43508e31c9dfcd50c914b42954d6dd8ca9` |
| SHA3-384 | `41220a4b9bc302e23a1fb1f4ec8d7da6dde876a0c08185349af307e6bc823c404ef159a71a79714c094c6faaab1f1b47` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17F454D5037EA25D9F0777E36D7EAB691EA3FB3737A06965B0600030F0622582DE53939` |
| SSDEEP | `24576:MFCXxEYN57lxPc2U90hkyz6R7L4rQTf7yT:pmYN57ly2U90/Q7crQHyT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_b3e188bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3e188bf57cbc7a25832ea1623180c43508e31c9dfcd50c914b42954d6dd8ca9"
    family = "unknown"
    file_name = "ae_mixtwo.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:44:02"
  condition:
    hash.sha256(0, filesize) == "b3e188bf57cbc7a25832ea1623180c43508e31c9dfcd50c914b42954d6dd8ca9"
}
```

### Sample 11: `8dcda89abe8d1192`

| Field | Value |
|---|---|
| SHA-256 | `8dcda89abe8d1192c60f5e2ce46af13ff4a73411eb2ad1311ff80fd54541c20b` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:42:58` |
| Reporter | `iamaachum` |
| Tags | `37-187-155-230, ClickFraud, exe, GCleaner, RemusStealer, sfx, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa5b9ea9f85fe1980f0f5063ce44cc0a` |
| SHA-1 | `d4b46417437b7be247b60df6c6804cbfe179ac21` |
| SHA-256 | `8dcda89abe8d1192c60f5e2ce46af13ff4a73411eb2ad1311ff80fd54541c20b` |
| SHA3-384 | `b1010611b22f60b052d249897a9605ea7d5b205db9d23a526954e04bfa2ea79acd44df22fb5d3afca9f68cc59537be6d` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1E3F63308EFD470B6FD639231CEB786D4DA39BC06076096EB17A0945B1DB72D1CA36722` |
| SSDEEP | `393216:3Gyl/dRToAPS2wRg1CKID+EFXXhEMXZfD9KEhxyrltKUeZOxc:2yl/DSf8CXD+4HXXZ4EhkZtKUeoe` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_011_8dcda89a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dcda89abe8d1192c60f5e2ce46af13ff4a73411eb2ad1311ff80fd54541c20b"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:42:58"
  condition:
    hash.sha256(0, filesize) == "8dcda89abe8d1192c60f5e2ce46af13ff4a73411eb2ad1311ff80fd54541c20b"
}
```

### Sample 12: `fd207faa41eb1537`

| Field | Value |
|---|---|
| SHA-256 | `fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f` |
| Family label | `Mirai` |
| File name | `fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f.elf` |
| File type | `elf` |
| First seen | `2026-08-22 01:36:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e39f4494e945052735e488ca08362b69` |
| SHA-1 | `ead8f2c76d165152fef4a177f55ff3f8979c5b95` |
| SHA-256 | `fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f` |
| SHA3-384 | `5b27829d52f6e0cb3bbab6fe401b6a484651cad649ddd48644a406af63edac6ffd0bf3ab9fb49f929daed7d0e8322563` |
| TLSH | `T181E31A46AB409B13C1D21B76FADF42063323DB5493A7730659286FF43F87A9E0E67606` |
| TELFHASH | `t12b211e2666ba981a7f718c60ddbc9bf21562131623442a32df3ac5dc182a086f52ac1f` |
| SSDEEP | `3072:+IzEBLK3wvdwVj2oEax0Zs6xVrwmOD1+K8da6PjjM/90/gZF:+aEBWgOtBEax0Zs6xlwmqya6PvM/90/i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_fd207faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f"
    family = "Mirai"
    file_name = "fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 01:36:09"
  condition:
    hash.sha256(0, filesize) == "fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f"
}
```

### Sample 13: `749d02aacf954ce9`

| Field | Value |
|---|---|
| SHA-256 | `749d02aacf954ce95077efc5084679a11ee474799b9961c069413f60278ab854` |
| Family label | `ValleyRAT` |
| File name | `F7120F15B4B3E4622E8EAF5E8F664D0C.dll` |
| File type | `dll` |
| First seen | `2026-08-22 01:35:19` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7120f15b4b3e4622e8eaf5e8f664d0c` |
| SHA-1 | `d6ce7e20055785107487688bb02af1ca03afcbc4` |
| SHA-256 | `749d02aacf954ce95077efc5084679a11ee474799b9961c069413f60278ab854` |
| SHA3-384 | `a569b1c31dc8a643a648d0e7498e8fc696ad02b55653dd2d50792f36b027a30739f317deb2b9123a42ff3567b044ecb4` |
| IMPHASH | `02fa2764e23c77b35791c75ad19fce09` |
| TLSH | `T13246CF113D9C40B7F1DF12318F68AABCF2AE7DB03A7630971690F61AF9367414A1856B` |
| SSDEEP | `98304:uvH5fmBMIxE74yzlpJFYd8rkdB9msvlm9cLD1Z4OiZrq1DfPHNADtV6v+zM+rwru:uP61sYdB9msY9cNZ4O7NADtV6v+zZR3B` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_013_749d02aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749d02aacf954ce95077efc5084679a11ee474799b9961c069413f60278ab854"
    family = "ValleyRAT"
    file_name = "F7120F15B4B3E4622E8EAF5E8F664D0C.dll"
    file_type = "dll"
    first_seen = "2026-08-22 01:35:19"
  condition:
    hash.sha256(0, filesize) == "749d02aacf954ce95077efc5084679a11ee474799b9961c069413f60278ab854"
}
```

### Sample 14: `fd01de8844ac6f7c`

| Field | Value |
|---|---|
| SHA-256 | `fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175` |
| Family label | `unknown` |
| File name | `fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175` |
| File type | `sh` |
| First seen | `2026-08-22 01:30:25` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0fe3d7580a571516378825c008a7618b` |
| SHA-1 | `6d3320dc8458fcfea9546cb6503f55946707ef6d` |
| SHA-256 | `fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175` |
| SHA3-384 | `725e6cb52638c1841eaaa934824a36830b79b8190f4e2d389a21fa8ca0915474c02fca6bd80d5a8e1276944a51cd4d0b` |
| TLSH | `T106316FEE10111A371182CAAE33A37688B28DE6F7685FD7E4DC190DB9438838DF161F59` |
| SSDEEP | `24:Nd/td27YO5yRyRFxtURA17pZ7a/wZcpOQK0fRbIHY2:Nd/td27YOJ6RAJl6OQK0FI42` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_fd01de88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175"
    family = "unknown"
    file_name = "fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175"
    file_type = "sh"
    first_seen = "2026-08-22 01:30:25"
  condition:
    hash.sha256(0, filesize) == "fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175"
}
```

### Sample 15: `68646c5e06443730`

| Field | Value |
|---|---|
| SHA-256 | `68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70` |
| Family label | `unknown` |
| File name | `68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70` |
| File type | `sh` |
| First seen | `2026-08-22 01:30:19` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2db28f19edb47ade7a41d14ad061cbea` |
| SHA-1 | `f80527746d5040223a11db20a701c4ef4afbb357` |
| SHA-256 | `68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70` |
| SHA3-384 | `5b14bd112d9bb3f77e4dd30c0ad8b11b23bc05261d4c039b5e7b36c0cb4f1647f83b53ea707536d8eb71f7e12c99981e` |
| TLSH | `T18D3146DA04111E702112CD8E73B23548B38DE5FB3D9FCBD4D8894EA992487CCF262B5A` |
| SSDEEP | `24:G1EEXESwb4DzJM4LUdD4oHcpq6qgafFt4:GSEXESe43UvHctf8Fu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_68646c5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70"
    family = "unknown"
    file_name = "68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70"
    file_type = "sh"
    first_seen = "2026-08-22 01:30:19"
  condition:
    hash.sha256(0, filesize) == "68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70"
}
```

### Sample 16: `a2eb9cf201f057f9`

| Field | Value |
|---|---|
| SHA-256 | `a2eb9cf201f057f9860abfbd377b58d390165b6c86ff9a23f848ee0142b40f7b` |
| Family label | `Mirai` |
| File name | `bot.x86` |
| File type | `elf` |
| First seen | `2026-08-22 01:15:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bea4cc32e3a405ab8f5d298195b48f62` |
| SHA-1 | `45f4957618d474dd02ef935afe8b0ac9c472b546` |
| SHA-256 | `a2eb9cf201f057f9860abfbd377b58d390165b6c86ff9a23f848ee0142b40f7b` |
| SHA3-384 | `7e19e7a89a400e5ba49fdefa2355ff13ce5acac29c608c9f5d436310500f02ba896577b0dc2644f514ad11713f975100` |
| TLSH | `T14F536C8256C3F8B2F823007D20AF5BB25A73E43AA062DF9AD3D95976DC15211E32775C` |
| TELFHASH | `t1a131f3fa1dbb0dbcb3d0b540c21a9bd31d3ada77186135f141b2ad4637f2e12816a839` |
| SSDEEP | `1536:MxTSUCclxCZJZ0Jb77ikyLDsRAD98MdefErBR:MxTnBxCZb0JbXTyfTD6MQAR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_a2eb9cf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2eb9cf201f057f9860abfbd377b58d390165b6c86ff9a23f848ee0142b40f7b"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-22 01:15:58"
  condition:
    hash.sha256(0, filesize) == "a2eb9cf201f057f9860abfbd377b58d390165b6c86ff9a23f848ee0142b40f7b"
}
```

### Sample 17: `60507a4f30c4b1f8`

| Field | Value |
|---|---|
| SHA-256 | `60507a4f30c4b1f8667be1b809caa854f65661b3741054fa73e133d3944a402e` |
| Family label | `ValleyRAT` |
| File name | `DDAA70755BF4E96F0A21663D55D978A0.dll` |
| File type | `dll` |
| First seen | `2026-08-22 01:15:19` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddaa70755bf4e96f0a21663d55d978a0` |
| SHA-1 | `2e995323a921ef5473031e6c96f825934ccbbea6` |
| SHA-256 | `60507a4f30c4b1f8667be1b809caa854f65661b3741054fa73e133d3944a402e` |
| SHA3-384 | `c3eae71b6804f7b4610c82f0506b7f420aa8de6ef2d5fe5288cb717fe8234f237749d48dcfae5527d057d57664e68429` |
| IMPHASH | `02fa2764e23c77b35791c75ad19fce09` |
| TLSH | `T11646CF113D9C40B7F1DF12318F68AABCF2AE7DB03A7630971690F61AF9367414A1856B` |
| SSDEEP | `98304:uvH5fmBMIxE74yzlpJFYd8rkdB9mcvlm9cLD1Z4OiZrq1DfPHNADtV6v+zM+rwru:uP61sYdB9mcY9cNZ4O7NADtV6v+zZR3B` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_017_60507a4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60507a4f30c4b1f8667be1b809caa854f65661b3741054fa73e133d3944a402e"
    family = "ValleyRAT"
    file_name = "DDAA70755BF4E96F0A21663D55D978A0.dll"
    file_type = "dll"
    first_seen = "2026-08-22 01:15:19"
  condition:
    hash.sha256(0, filesize) == "60507a4f30c4b1f8667be1b809caa854f65661b3741054fa73e133d3944a402e"
}
```

### Sample 18: `5239ca97f24a7b84`

| Field | Value |
|---|---|
| SHA-256 | `5239ca97f24a7b84ec35362adcca03935e29bc9082e3aa69c5ac73c7ac2efb19` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:13:23` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d92f9f7bf243b194e4aca8ff85fb570` |
| SHA-1 | `856035f2837753f203cc2a885d5f6b2e53d308e8` |
| SHA-256 | `5239ca97f24a7b84ec35362adcca03935e29bc9082e3aa69c5ac73c7ac2efb19` |
| SHA3-384 | `1726b040c8ddb17aa9f98bb7008c2232afed1493a10dcbcd9d3b82af25f56d55044b14290e716cb546a6222c79a3e087` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1D5E63342A7B874F8F0B2D8708C0CD711F7757C89AA60D99F1799EAA72F32500A92D735` |
| SSDEEP | `393216:zGylv0yxPSxqLMtZhizsHJ+1chjTH3nd/KS:6yl8yJzEZgUU1+TX5j` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_018_5239ca97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5239ca97f24a7b84ec35362adcca03935e29bc9082e3aa69c5ac73c7ac2efb19"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:13:23"
  condition:
    hash.sha256(0, filesize) == "5239ca97f24a7b84ec35362adcca03935e29bc9082e3aa69c5ac73c7ac2efb19"
}
```

### Sample 19: `9f4e2dc6f2aeeb95`

| Field | Value |
|---|---|
| SHA-256 | `9f4e2dc6f2aeeb950936285e8e47f805d4e3d843e0912df08f49dc6e53bdf152` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:12:10` |
| Reporter | `iamaachum` |
| Tags | `37-187-155-230, ClickFraud, exe, GCleaner, RemusStealer, sfx, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a629b59531a0780aeca540022274541f` |
| SHA-1 | `e2024640bbdabd720dcb2464de2e03e7dca2eb9d` |
| SHA-256 | `9f4e2dc6f2aeeb950936285e8e47f805d4e3d843e0912df08f49dc6e53bdf152` |
| SHA3-384 | `18dc45106ad825a4d29e1562458bde75d585604c6a78a9fb8b12ce123439db59e76f8b8f6f7b6bad6b24b3cc7a3b2034` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T174073314EB9420F5FC72D131CAB34BE1D9327846072066EB3B9079A75EF7295CA36722` |
| SSDEEP | `393216:oGylmOkvbt+C1CRwPsUto4GkF9fwYFSW48o4Q4Y3RsW8s:VylzU1ZsUTF9YYzrop4/3s` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_019_9f4e2dc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f4e2dc6f2aeeb950936285e8e47f805d4e3d843e0912df08f49dc6e53bdf152"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:12:10"
  condition:
    hash.sha256(0, filesize) == "9f4e2dc6f2aeeb950936285e8e47f805d4e3d843e0912df08f49dc6e53bdf152"
}
```

### Sample 20: `c2dd350977077076`

| Field | Value |
|---|---|
| SHA-256 | `c2dd3509770770764b86e5ac7dacd4805ceed98708b27a208a4973e3d4f7c3ea` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:11:08` |
| Reporter | `iamaachum` |
| Tags | `37-187-155-230, ClickFraud, exe, GCleaner, RemusStealer, sfx, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffc7dd7ffc6c89b3c0d26180ea256902` |
| SHA-1 | `a8765c87a9587452017b83c37ca6443049b5e917` |
| SHA-256 | `c2dd3509770770764b86e5ac7dacd4805ceed98708b27a208a4973e3d4f7c3ea` |
| SHA3-384 | `033d66516684795ecb45a446fc0acee97aff3a490f22cf85bf5dbb579133a1ab27102d6c28b3d767f3d09efa78143f84` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1A3F63305FB9471B2FC769634DFF396E0EA31784A076286FA1B90755B0AE70D1CA36312` |
| SSDEEP | `393216:YGylhmeIB35ZuWSbF+qUn7ASk4DB35frOTBFkIaGWuJszRH:lylW7SbFIdrJifkIF1QRH` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_020_c2dd3509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2dd3509770770764b86e5ac7dacd4805ceed98708b27a208a4973e3d4f7c3ea"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:11:08"
  condition:
    hash.sha256(0, filesize) == "c2dd3509770770764b86e5ac7dacd4805ceed98708b27a208a4973e3d4f7c3ea"
}
```

### Sample 21: `74a9d856028ed2da`

| Field | Value |
|---|---|
| SHA-256 | `74a9d856028ed2daf9b4ac1db1f6da9ca8140599d0e3cf223687d15ee66f3c0f` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:10:01` |
| Reporter | `iamaachum` |
| Tags | `37-187-155-230, ClickFraud, exe, GCleaner, RemusStealer, sfx, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23a8d5e176ed683111fe79bdcd435521` |
| SHA-1 | `8e6861c1b11e326b59051a0d0bac8d43544485da` |
| SHA-256 | `74a9d856028ed2daf9b4ac1db1f6da9ca8140599d0e3cf223687d15ee66f3c0f` |
| SHA3-384 | `790f65ef56eced37df142e194f68f0bd4fa13f5199483ef4e5324209c36384247ac1bb34dbc5e484db67ee9318d3fcbf` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1F6E6331AB79074F8F061D9708929DB01F7757C86AB30C96A17ECEB6B2FA2050D62D371` |
| SSDEEP | `393216:bsSifdUGYt00rTtWq5Z75erRvVbvdD/pf47uv85r:QSoV0/75N5erRNLdD/pQ79` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_021_74a9d856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74a9d856028ed2daf9b4ac1db1f6da9ca8140599d0e3cf223687d15ee66f3c0f"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:10:01"
  condition:
    hash.sha256(0, filesize) == "74a9d856028ed2daf9b4ac1db1f6da9ca8140599d0e3cf223687d15ee66f3c0f"
}
```

### Sample 22: `a4da7669180c6c0c`

| Field | Value |
|---|---|
| SHA-256 | `a4da7669180c6c0cbd4c20bcf12906bccec11233e950a90942d20d3984fe2d94` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:08:46` |
| Reporter | `iamaachum` |
| Tags | `37-187-155-230, ClickFraud, exe, GCleaner, RemusStealer, sfx, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d5826c79f047865e675ffd31d92d829` |
| SHA-1 | `1b2943164c8698e53d7cdac3cefede61bb4a5496` |
| SHA-256 | `a4da7669180c6c0cbd4c20bcf12906bccec11233e950a90942d20d3984fe2d94` |
| SHA3-384 | `ea3e87f14a03bc19adcd51318b87802836473272cb5c85ce5d3ba4afc3ca7b016fc342443f3d2f3cde56470276120039` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T11FE63308EFE831BDFDB25771CEB78AD2C920B84A03518AEB1BC4A1574EBB551C936711` |
| SSDEEP | `393216:lsSbfdU/ftS8KusZsdaKOBYZsIhMJX5WOm3XCWj/:mSWftS8hKoOBYZuJX5WxXtj/` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_022_a4da7669
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4da7669180c6c0cbd4c20bcf12906bccec11233e950a90942d20d3984fe2d94"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:08:46"
  condition:
    hash.sha256(0, filesize) == "a4da7669180c6c0cbd4c20bcf12906bccec11233e950a90942d20d3984fe2d94"
}
```

### Sample 23: `42c2c18036a33df2`

| Field | Value |
|---|---|
| SHA-256 | `42c2c18036a33df2229285065cdcbd7d6fbfd1cdbb9b121fc0160f98c075add7` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:07:38` |
| Reporter | `iamaachum` |
| Tags | `37-187-155-230, ClickFraud, exe, GCleaner, RemusStealer, sfx, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4dda8f314cc90279dfbb432eb39a868a` |
| SHA-1 | `6ef3420028f394c62bf52e4b297fcfe004ad124c` |
| SHA-256 | `42c2c18036a33df2229285065cdcbd7d6fbfd1cdbb9b121fc0160f98c075add7` |
| SHA3-384 | `e84f4fd10fc530bfca7aacf498c4204775e0fbb27506770d170b0b39494867dd789290e9ec20c6cf29777f7681492c0d` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1B9F6334AA3D430EDE0A2C970898A9711F735BCD5AF20CAAF1795F9275F72654A03C339` |
| SSDEEP | `393216:OsSRdRToAtLS42IsAF+qpOfpW8GVVmdT4IcmnSddqOOZ:hSRlsAF/EHd8Ic6SdVOZ` |
| ICON-DHASH | `96e0cce4d4cce08e` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_023_42c2c180
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42c2c18036a33df2229285065cdcbd7d6fbfd1cdbb9b121fc0160f98c075add7"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:07:38"
  condition:
    hash.sha256(0, filesize) == "42c2c18036a33df2229285065cdcbd7d6fbfd1cdbb9b121fc0160f98c075add7"
}
```

### Sample 24: `e1ceb7fc212e1822`

| Field | Value |
|---|---|
| SHA-256 | `e1ceb7fc212e182239ef470559bc0ee09c8fb12fa69f6ae09dee072bfecfb2b9` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:05:26` |
| Reporter | `iamaachum` |
| Tags | `37-187-155-230, ClickFraud, exe, GCleaner, RemusStealer, sfx, Stealc, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c0d3b44d58ce70320bce8aefb49499a` |
| SHA-1 | `6defb66e800e635a8d95851f847737ce15ddafcc` |
| SHA-256 | `e1ceb7fc212e182239ef470559bc0ee09c8fb12fa69f6ae09dee072bfecfb2b9` |
| SHA3-384 | `a7c34998269be504bec6d80d2cc2dc8c16aa5c8292b85b1f6e142a9083ccc73127f79690a0af8db54f5efb03c507884d` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T15456230AE79431FCF066D8748946E701E7713C886B30DAAB1794EE6B2FA3150D92D736` |
| SSDEEP | `98304:06IZrVRusbgSRcdVLl8AZk2RuqtOxITsns2ophynSaXzjX7JUUE3NQANqmAPPm:0fsSRMhS2RboIoPophynSE7GNqb3m` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_024_e1ceb7fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1ceb7fc212e182239ef470559bc0ee09c8fb12fa69f6ae09dee072bfecfb2b9"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:05:26"
  condition:
    hash.sha256(0, filesize) == "e1ceb7fc212e182239ef470559bc0ee09c8fb12fa69f6ae09dee072bfecfb2b9"
}
```

### Sample 25: `e63dc60b24b94658`

| Field | Value |
|---|---|
| SHA-256 | `e63dc60b24b94658992abec4e5819be35bc0ed5bfc3fe65a89f320539236a181` |
| Family label | `ValleyRAT` |
| File name | `CFDD3706B8A218872E16A5F496617398.dll` |
| File type | `dll` |
| First seen | `2026-08-22 01:05:10` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfdd3706b8a218872e16a5f496617398` |
| SHA-1 | `af146c7b4cf4689f2307ee55a90915fa7e8b91a5` |
| SHA-256 | `e63dc60b24b94658992abec4e5819be35bc0ed5bfc3fe65a89f320539236a181` |
| SHA3-384 | `f1a087e92b53af32745b3675783a4383f438e386e0679230461fdde53dc8a043935d4884379d6463e7b3d0c9bdceb87b` |
| IMPHASH | `ded26d33ae9a6077eea99e272c4c8255` |
| TLSH | `T18656D0313D5D009EE0AA12398F68AAEDF2FE7DA03BB531571980F639FB35B414A1415B` |
| SSDEEP | `98304:g2C7uzfNvxse6NjjsAI+jEqkKmHhpXFxr5n6fyq+nkDOByQfoOiGBx5A2NwKEYos:lV9GAqkKmHhpXFxr5n6fyq+nkDOByQf3` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_025_e63dc60b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e63dc60b24b94658992abec4e5819be35bc0ed5bfc3fe65a89f320539236a181"
    family = "ValleyRAT"
    file_name = "CFDD3706B8A218872E16A5F496617398.dll"
    file_type = "dll"
    first_seen = "2026-08-22 01:05:10"
  condition:
    hash.sha256(0, filesize) == "e63dc60b24b94658992abec4e5819be35bc0ed5bfc3fe65a89f320539236a181"
}
```

### Sample 26: `47630a069e44a698`

| Field | Value |
|---|---|
| SHA-256 | `47630a069e44a6981ac37e9d82ae44e7252ed184ccb30f41f2df56f26254bd40` |
| Family label | `RemusStealer` |
| File name | `ae_mixtwo.exe` |
| File type | `exe` |
| First seen | `2026-08-22 01:03:55` |
| Reporter | `iamaachum` |
| Tags | `exe, GCleaner, RemusStealer, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85409b2ac42cfcb53ea6835ea0c9f143` |
| SHA-1 | `5b3628e224cb4c647f9ce604fa3695d66cf451e5` |
| SHA-256 | `47630a069e44a6981ac37e9d82ae44e7252ed184ccb30f41f2df56f26254bd40` |
| SHA3-384 | `95d8625ea96589ca2bbcec9c54bf59ff6c199c83fd292599f2130c2555f237cf6ae109e6367ed30dc053bf7371a5f28d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T164656D242BE925D5F03BBE37DAEA7186DB3BB3737A0B934B1150034B1562681CE93539` |
| SSDEEP | `24576:UgFvKIR7ENnw6rSI0Bren4EGJQ95+o6G7AIwgtZF5dS7GfZVpA:Ur6YFw6rSIIMfGJQepg/dtZk` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_026_47630a06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47630a069e44a6981ac37e9d82ae44e7252ed184ccb30f41f2df56f26254bd40"
    family = "RemusStealer"
    file_name = "ae_mixtwo.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:03:55"
  condition:
    hash.sha256(0, filesize) == "47630a069e44a6981ac37e9d82ae44e7252ed184ccb30f41f2df56f26254bd40"
}
```

### Sample 27: `4da675a2133e1b05`

| Field | Value |
|---|---|
| SHA-256 | `4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c` |
| Family label | `Mirai` |
| File name | `4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c.elf` |
| File type | `elf` |
| First seen | `2026-08-22 01:01:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a8e93dc20600f56be4c2329d51af7f3` |
| SHA-1 | `2436459a8abddf4ffe2b853d604ab44579c829aa` |
| SHA-256 | `4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c` |
| SHA3-384 | `1dd5cf7cd1a063620b5f68d8f7e4ade308acd5f7479a5a7a5c5c34a57a1094224cce7fd8d2c4c7d22c5d6287e905a218` |
| TLSH | `T1A9735C21AE25082BC1C0A57E71F38731F6F6534F6578862A7CB10F9C6F68640366F7A6` |
| SSDEEP | `1536:M4Zyrt3kSD+O1VAr0d8908tLAdNk5YtaH:Lgqr+OxAdNUhH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_4da675a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c"
    family = "Mirai"
    file_name = "4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c.elf"
    file_type = "elf"
    first_seen = "2026-08-22 01:01:06"
  condition:
    hash.sha256(0, filesize) == "4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c"
}
```

### Sample 28: `3db21013142719a5`

| Field | Value |
|---|---|
| SHA-256 | `3db21013142719a5845a82e09d29e975f80caffa5649b5e4e7e6f3c229d0feb4` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:53:52` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c71812b9333a66da41f16c26cebd28c0` |
| SHA-1 | `8bd7037b448114e2b8145ab9127cb1d55fd0acaa` |
| SHA-256 | `3db21013142719a5845a82e09d29e975f80caffa5649b5e4e7e6f3c229d0feb4` |
| SHA3-384 | `b5ba62b2ac4403fc1cade70d6ce018611e2897b584d05fcd2a508c20e72cfd37cb4147109f4652beb1d6a321d4b030dc` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T17616120AA79030EDF162D9748956D701F7313C89AB70CAAB27D8FA6B2F63150D82D735` |
| SSDEEP | `98304:X2zGk6YwlC1CtbVdhKawXPolJaDLLB1SRLNEp+9MGsOo:130CdonXG4Z1ls9MGsOo` |
| ICON-DHASH | `00f1f8f86cd89a00` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_028_3db21013
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3db21013142719a5845a82e09d29e975f80caffa5649b5e4e7e6f3c229d0feb4"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:53:52"
  condition:
    hash.sha256(0, filesize) == "3db21013142719a5845a82e09d29e975f80caffa5649b5e4e7e6f3c229d0feb4"
}
```

### Sample 29: `3ef0276b36b843e6`

| Field | Value |
|---|---|
| SHA-256 | `3ef0276b36b843e6e1e39065d9c413d45515f09cd115f3c0e1dc25b227fc3e9d` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:53:06` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54abb47f1f95155271296477f028c61e` |
| SHA-1 | `df1fcf3005cc483bbf249987ce8744ac4e189773` |
| SHA-256 | `3ef0276b36b843e6e1e39065d9c413d45515f09cd115f3c0e1dc25b227fc3e9d` |
| SHA3-384 | `0e1341e85e85d869d3df5dec80860db0eb25b93aa8ef0bda7801df0405010a8c3ebf54c0bca0df47d955009aacc6f5fd` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1991602076B4024EEE071EBB84546D325E2B13D84BB31C9A727B4EA677FD71416E2C6E0` |
| SSDEEP | `49152:fgTbH94Yx1gfpqmS5PmNf/0S/PuPVu94rbR6PNUqR0TSxlM4Dp9ciwBg60jHFu04:o2fWkFPuuKoCg0TvFTBgvHFu0g3` |
| ICON-DHASH | `f0486178787039b4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_029_3ef0276b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ef0276b36b843e6e1e39065d9c413d45515f09cd115f3c0e1dc25b227fc3e9d"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:53:06"
  condition:
    hash.sha256(0, filesize) == "3ef0276b36b843e6e1e39065d9c413d45515f09cd115f3c0e1dc25b227fc3e9d"
}
```

### Sample 30: `31611a93846b3d23`

| Field | Value |
|---|---|
| SHA-256 | `31611a93846b3d2307c7640e5bf04416ce3b0d337db0db5f69cdb408ca3be5d6` |
| Family label | `NeedleStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:51:59` |
| Reporter | `iamaachum` |
| Tags | `dubl2allremriki-com, exe, NeedleStealer, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d475185ce3d373eee45f60824742db13` |
| SHA-1 | `86ff4b770bd6afcdcc8f5c49a12e1cbb7b71a57a` |
| SHA-256 | `31611a93846b3d2307c7640e5bf04416ce3b0d337db0db5f69cdb408ca3be5d6` |
| SHA3-384 | `afaf4f490946a6d7b720bfb79e7ef96af09011e7f38b6df59d55983bbc49234fcc341131776893a52646e8121d4e8163` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1A3463947EC9546A9D0AED231C6629263BA717C485F3023D72F60F7382FB6BD46AB5700` |
| SSDEEP | `49152:Q4DPhAZ6Yb4/wv5AxkbDcRsM3Ll2ylEK46Aq+hanB5Enki500rk8Vg2ig:M6+B2sM3ETKGSEnhtQ` |

#### Technical Assessment

- The sample is tracked as `NeedleStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NeedleStealer_030_31611a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31611a93846b3d2307c7640e5bf04416ce3b0d337db0db5f69cdb408ca3be5d6"
    family = "NeedleStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:51:59"
  condition:
    hash.sha256(0, filesize) == "31611a93846b3d2307c7640e5bf04416ce3b0d337db0db5f69cdb408ca3be5d6"
}
```

### Sample 31: `b95ac535ed7651f4`

| Field | Value |
|---|---|
| SHA-256 | `b95ac535ed7651f441589fb37db059d76bc2384c417e910fc264aa006d115c49` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:51:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6bbd1507bde25eb86d8e62782248d17` |
| SHA-1 | `b528fa856d48cce19a8d6c7e17c83c498152a1a7` |
| SHA-256 | `b95ac535ed7651f441589fb37db059d76bc2384c417e910fc264aa006d115c49` |
| SHA3-384 | `e54dd17428e3417dfdc3d75027273bab94b294f5714a0a2c39d738c5153d3a118c071c159286ff413b0e3161d60de74c` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T16FD63302A76121ECF122D8304986D711F7317C898B31DEAB2BE8FA5B6F53550E92D736` |
| SSDEEP | `393216:4hzXRnnABvxd8suimFptNzlTeaywI+jKtc7ZR:4hVnaL8sJmzpTDjl7ZR` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_031_b95ac535
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95ac535ed7651f441589fb37db059d76bc2384c417e910fc264aa006d115c49"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:51:10"
  condition:
    hash.sha256(0, filesize) == "b95ac535ed7651f441589fb37db059d76bc2384c417e910fc264aa006d115c49"
}
```

### Sample 32: `ae9200450fb3030b`

| Field | Value |
|---|---|
| SHA-256 | `ae9200450fb3030b59e0a5a27eb2ab413297f0a0bdb4cb8a6755e64f38a07ff5` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:50:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49018ec231c35909dff5ebf51d31d478` |
| SHA-1 | `bc6ff9fd63ddbc0027dfa61873908211ddacfff1` |
| SHA-256 | `ae9200450fb3030b59e0a5a27eb2ab413297f0a0bdb4cb8a6755e64f38a07ff5` |
| SHA3-384 | `ea876155e2896d0106cf6ed7311f963746c7a2e0d46cba74c32c51609989cd03e5456be981ea22c7fe96ca79d3ba6db7` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T15CD6331AF3E060FDF076D8708946CB12E7327C45A771D9BA1798FE971F82241AA29731` |
| SSDEEP | `196608:rZNU4cpqE+YaIxhpOP9wG9beIJZERwUGKcaEHzb8EtyRRJmOVJa7+uxmYmF:tG4+qeayfOlL9bfLjsR1VJa/mv` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_032_ae920045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae9200450fb3030b59e0a5a27eb2ab413297f0a0bdb4cb8a6755e64f38a07ff5"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:50:30"
  condition:
    hash.sha256(0, filesize) == "ae9200450fb3030b59e0a5a27eb2ab413297f0a0bdb4cb8a6755e64f38a07ff5"
}
```

### Sample 33: `8e2f9c7c115d3137`

| Field | Value |
|---|---|
| SHA-256 | `8e2f9c7c115d3137f5c993b0178395bca50aad733abc1ad336678b274662d4b6` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:49:14` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4522587b220a25e4c7d7156790c9f97d` |
| SHA-1 | `1a05f20178c75ca8b44aa7e3b305de2f05bd0873` |
| SHA-256 | `8e2f9c7c115d3137f5c993b0178395bca50aad733abc1ad336678b274662d4b6` |
| SHA3-384 | `d25e96d62816aea8ed25126fd9eb180fe9a0d60d8751830cf35438a93c31a056355574b98958e639567e39a2f725dad7` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1AFD633046BA43166ED738274CEB787E0DE603C1A471087EB3B99B49B5FF7581C626722` |
| SSDEEP | `196608:rFPlBSw+jcCVVXvxLQzPobv/uzV/eYvmw3S5MsqPu4f/oyjdylxncC:xPlBozbB0sezVJvmw3IJerVjwxncC` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_033_8e2f9c7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e2f9c7c115d3137f5c993b0178395bca50aad733abc1ad336678b274662d4b6"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:49:14"
  condition:
    hash.sha256(0, filesize) == "8e2f9c7c115d3137f5c993b0178395bca50aad733abc1ad336678b274662d4b6"
}
```

### Sample 34: `3295712cfe22112e`

| Field | Value |
|---|---|
| SHA-256 | `3295712cfe22112ee05a194478533ae0beb4ab46b0f5b38c75c09beb865b8bd7` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:48:18` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e036d2f0d39d32b4211def66dcc35d` |
| SHA-1 | `0ccd3b9b17e7fb71448511587ce0b9c0bb37879b` |
| SHA-256 | `3295712cfe22112ee05a194478533ae0beb4ab46b0f5b38c75c09beb865b8bd7` |
| SHA3-384 | `015082b26562341125f733384d63a80d01946b4a919facb26d2415db665f2824bed78fff95c249ae5501644e81d966fc` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T150D63346E75020FDE067DA70868AEB41E3367C89A7709A6B13C4FE5B2FA2140E43D775` |
| SSDEEP | `196608:rRg7HIq9UkcSzMlpsO+SKU5kMc6xPqeYkJ/1Zz/UMuXNBwubfYGP:1Dq9Uk3zMLsQXYkJ3z/UAWYg` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_034_3295712c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3295712cfe22112ee05a194478533ae0beb4ab46b0f5b38c75c09beb865b8bd7"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:48:18"
  condition:
    hash.sha256(0, filesize) == "3295712cfe22112ee05a194478533ae0beb4ab46b0f5b38c75c09beb865b8bd7"
}
```

### Sample 35: `586453165bf6649d`

| Field | Value |
|---|---|
| SHA-256 | `586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883` |
| Family label | `unknown` |
| File name | `586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:46:14` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `821ddd4cc1cf22265a5448532a03e8d1` |
| SHA-1 | `14f3703462190e1b607c210e90f820347acdbf52` |
| SHA-256 | `586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883` |
| SHA3-384 | `4e3ecf9ab25e8ba0aea31e4b5966e08aa1c333ecb4a499b5248830be9d0520ec46c2395ad4bbdd8f9c7c05f2ab77f831` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1E4764913799541E4C4AADF34C47382537A60F88DDB3523936E61BA342FB97C2AD7AB04` |
| SSDEEP | `24576:GUjUxpZ1xROpMGFZuEapcvf+GeX51eLFSZ7aZO/AR826itWZu1N0J/bmMlKcVmM+:BUxoNxNvf7LZZ+AFtr1CjmNAv4z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_58645316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883"
    family = "unknown"
    file_name = "586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:46:14"
  condition:
    hash.sha256(0, filesize) == "586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883"
}
```

### Sample 36: `8a613f3578531c2c`

| Field | Value |
|---|---|
| SHA-256 | `8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000` |
| Family label | `Mirai` |
| File name | `8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000.elf` |
| File type | `elf` |
| First seen | `2026-08-22 00:46:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f162e51659c53eda7eba78059a5b81b5` |
| SHA-1 | `32a8ca1d08b5459cb1e37d55e7f196322dfa7ca8` |
| SHA-256 | `8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000` |
| SHA3-384 | `4a4b7d9c64dfa040358bfb046439d192292f1f7e4e05f745019d10ea64b92975db3c964fb6888c5a2086ea9796f9fe58` |
| TLSH | `T1B2732B96B841AB21D6C246B7FE0F110E73174B6CE3DE73125D185B70778B86B0E6B60A` |
| TELFHASH | `t1a51199648f001aec2b70cc8c86eeb37735963db5ff23596a069b9e99c7226d1a01240d` |
| SSDEEP | `1536:QQnheEIX8IUHbm3Aea1rIwsVCc3Pqat444MOhiTZ4aZUz0xM5KYi:YEIX8IUHK3AJIwsV3PqatuAZ4aZULMZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_8a613f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000"
    family = "Mirai"
    file_name = "8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000.elf"
    file_type = "elf"
    first_seen = "2026-08-22 00:46:07"
  condition:
    hash.sha256(0, filesize) == "8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000"
}
```

### Sample 37: `11974ece6c707759`

| Field | Value |
|---|---|
| SHA-256 | `11974ece6c707759b83574eaf844a6fbeebb55c16ac2b5b81d89d7200905733e` |
| Family label | `ValleyRAT` |
| File name | `ABFCAB533D0BB4F3D44677FE84CE87BF.dll` |
| File type | `dll` |
| First seen | `2026-08-22 00:40:11` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abfcab533d0bb4f3d44677fe84ce87bf` |
| SHA-1 | `d1a4a388ebb5edf6b54e8790828fed41c2bb1e2e` |
| SHA-256 | `11974ece6c707759b83574eaf844a6fbeebb55c16ac2b5b81d89d7200905733e` |
| SHA3-384 | `a3490fdb0b18c4bcdec69853b0fa79bc5cc007ef9f637b84f6fdf28234005ceeeb14c61efda5386d813d7d9ddb8ef20c` |
| IMPHASH | `ded26d33ae9a6077eea99e272c4c8255` |
| TLSH | `T13D56D0313D5D009EE0AA12398F68AAEDF2FE7DA03BB531571980F639FB35B414A1415B` |
| SSDEEP | `98304:g2C7uzfNvxse6NjjsAI+jEqkKmHIpXFxr5n6fyq+nkDOByQfoOiGBx5A2NwKEYos:lV9GAqkKmHIpXFxr5n6fyq+nkDOByQf3` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_037_11974ece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11974ece6c707759b83574eaf844a6fbeebb55c16ac2b5b81d89d7200905733e"
    family = "ValleyRAT"
    file_name = "ABFCAB533D0BB4F3D44677FE84CE87BF.dll"
    file_type = "dll"
    first_seen = "2026-08-22 00:40:11"
  condition:
    hash.sha256(0, filesize) == "11974ece6c707759b83574eaf844a6fbeebb55c16ac2b5b81d89d7200905733e"
}
```

### Sample 38: `4b9d68a24e5bf83e`

| Field | Value |
|---|---|
| SHA-256 | `4b9d68a24e5bf83ee32a8feb43a9b74b4955c35dce3564ae62a137b7101eb903` |
| Family label | `Socks5Systemz` |
| File name | `DCompAPI.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:38:26` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-Adware.DownloadAssistant, exe, Socks5Systemz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e939c7a99dbebfbbf1a8c1e0686b53f` |
| SHA-1 | `e3cc1674278ef7801fd6b05626e83243668dcba2` |
| SHA-256 | `4b9d68a24e5bf83ee32a8feb43a9b74b4955c35dce3564ae62a137b7101eb903` |
| SHA3-384 | `0948f12b97be6e5211613e303881464554c5e6955c0f70d9f460549a9d9ce185faaf34ec8037518ad55932a559dee7e1` |
| IMPHASH | `884310b1928934402ea6fec1dbd3cf5e` |
| TLSH | `T1D7F533C22892CD7BD615D238CC13A91464FDA7A75CF6114826ACFE906B774EBAC70387` |
| SSDEEP | `98304:I3jkgSZYbBx1FtoVr6BxwY4GddWlkNDWh13ZM:6tqABxwBGe8MA` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `Socks5Systemz` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Socks5Systemz_038_4b9d68a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b9d68a24e5bf83ee32a8feb43a9b74b4955c35dce3564ae62a137b7101eb903"
    family = "Socks5Systemz"
    file_name = "DCompAPI.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:38:26"
  condition:
    hash.sha256(0, filesize) == "4b9d68a24e5bf83ee32a8feb43a9b74b4955c35dce3564ae62a137b7101eb903"
}
```

### Sample 39: `78a2d2988751b159`

| Field | Value |
|---|---|
| SHA-256 | `78a2d2988751b159ab860349e3dd1a9f034f4f1ef4d39888b66a4c924b7e9db0` |
| Family label | `RemusStealer` |
| File name | `dollar.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:37:16` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38d66258740611f96675c49c6bb9f27d` |
| SHA-1 | `a3c01477303adc97a210ab141e698c9c102d37df` |
| SHA-256 | `78a2d2988751b159ab860349e3dd1a9f034f4f1ef4d39888b66a4c924b7e9db0` |
| SHA3-384 | `4b9459c537561d055fccbe209142036f309bf7c8f8dd5e9d017b5ccd2621ddcde275d1aeb6ec625e853f71546fc2fc67` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T102652302A7E444A6F775937588F583EE68703C423B35AA8F12C07A8E5EB7AD05D78353` |
| SSDEEP | `24576:/dVCygDxZR9uAa4OrxyIhi+ptKRw5Gzi8j5pqYxP64rCZdI:/dPWZR9uFLQIhTtKRafYt6tZd` |
| ICON-DHASH | `4176cad504000000` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_039_78a2d298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a2d2988751b159ab860349e3dd1a9f034f4f1ef4d39888b66a4c924b7e9db0"
    family = "RemusStealer"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:37:16"
  condition:
    hash.sha256(0, filesize) == "78a2d2988751b159ab860349e3dd1a9f034f4f1ef4d39888b66a4c924b7e9db0"
}
```

### Sample 40: `73e065dc63b3c7a0`

| Field | Value |
|---|---|
| SHA-256 | `73e065dc63b3c7a08f3f940ed7cbf761129767b191f78a9621f5b4d305cedc71` |
| Family label | `RemusStealer` |
| File name | `dollar.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:36:36` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdbf10a73965ecc2c73cf27aac159362` |
| SHA-1 | `c3abf0132795e05eb5bb97c39709da4786de0cf5` |
| SHA-256 | `73e065dc63b3c7a08f3f940ed7cbf761129767b191f78a9621f5b4d305cedc71` |
| SHA3-384 | `fe74cd13d84429a0f00c09f85b9f3d668cbbf33487bcad6e7dcd8345e51744471cff4ab5b9241b554493a2b877a711e5` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1F475232262D22922D1BAE3B4D4F341976D38B883AB75DDDF3184489D2A636C1BF35317` |
| SSDEEP | `49152:vAbJ8EU3/DQGaSgD5sPSmyCMuPJHj0vkaHkXN2eXrz:vAbJ8SdD5sPCmJ6kFXN` |
| ICON-DHASH | `b1f8ccb091f230b2` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_040_73e065dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73e065dc63b3c7a08f3f940ed7cbf761129767b191f78a9621f5b4d305cedc71"
    family = "RemusStealer"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:36:36"
  condition:
    hash.sha256(0, filesize) == "73e065dc63b3c7a08f3f940ed7cbf761129767b191f78a9621f5b4d305cedc71"
}
```

### Sample 41: `6a406376be3f0dc3`

| Field | Value |
|---|---|
| SHA-256 | `6a406376be3f0dc3c700a8c637b5c4a111c8e013b49f2100dace21520aeec4b8` |
| Family label | `RemusStealer` |
| File name | `526993537.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:35:41` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-RenPyLoader, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e32d60a5fb71b7a658d69b31402934f` |
| SHA-1 | `03340851d47839d344cfb8c1880aff5b164de902` |
| SHA-256 | `6a406376be3f0dc3c700a8c637b5c4a111c8e013b49f2100dace21520aeec4b8` |
| SHA3-384 | `b5dd225a4f7daf1d8a88a98f32760068dd0484cdbe7c816f9f66543f4ca1ab17c8f7edfb42be261b12ca7f9c6d659eb0` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T131365A07BCA545A9C0AAA734C9A787127B75BC88873233D72E50BA383F76BD05E75740` |
| SSDEEP | `49152:S+Ux99IDm1FYHvHW5pbEvBDFT1FUrg7TmXi:pQ9kci/0uJFFXb` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_041_6a406376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a406376be3f0dc3c700a8c637b5c4a111c8e013b49f2100dace21520aeec4b8"
    family = "RemusStealer"
    file_name = "526993537.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:35:41"
  condition:
    hash.sha256(0, filesize) == "6a406376be3f0dc3c700a8c637b5c4a111c8e013b49f2100dace21520aeec4b8"
}
```

### Sample 42: `b8557a6e283fc71c`

| Field | Value |
|---|---|
| SHA-256 | `b8557a6e283fc71cf39f68d2219a17599c2a6bd62d6c038aaacf10dc003d2408` |
| Family label | `unknown` |
| File name | `DCompAPI.exe` |
| File type | `unknown` |
| First seen | `2026-08-22 00:31:13` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-Adware.DownloadAssistant, Socks5Systemz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76af9931b3eadae96ceff5bb55cd60e6` |
| SHA-256 | `b8557a6e283fc71cf39f68d2219a17599c2a6bd62d6c038aaacf10dc003d2408` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_b8557a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8557a6e283fc71cf39f68d2219a17599c2a6bd62d6c038aaacf10dc003d2408"
    family = "unknown"
    file_name = "DCompAPI.exe"
    file_type = "unknown"
    first_seen = "2026-08-22 00:31:13"
  condition:
    hash.sha256(0, filesize) == "b8557a6e283fc71cf39f68d2219a17599c2a6bd62d6c038aaacf10dc003d2408"
}
```

### Sample 43: `7e21498244c5e0c0`

| Field | Value |
|---|---|
| SHA-256 | `7e21498244c5e0c07e45bf188b20fceb745d70470b48f2ea7d8fca87c53ab63c` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 00:31:02` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a1ef1a15d4e61aa4680c7e42653aa04` |
| SHA-256 | `7e21498244c5e0c07e45bf188b20fceb745d70470b48f2ea7d8fca87c53ab63c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_7e214982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e21498244c5e0c07e45bf188b20fceb745d70470b48f2ea7d8fca87c53ab63c"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 00:31:02"
  condition:
    hash.sha256(0, filesize) == "7e21498244c5e0c07e45bf188b20fceb745d70470b48f2ea7d8fca87c53ab63c"
}
```

### Sample 44: `27b9bb39d1f69c96`

| Field | Value |
|---|---|
| SHA-256 | `27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213` |
| Family label | `unknown` |
| File name | `27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213` |
| File type | `unknown` |
| First seen | `2026-08-22 00:27:24` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac3a06a63c2aa2f0bd0da0d175ac1478` |
| SHA-256 | `27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_27b9bb39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213"
    family = "unknown"
    file_name = "27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213"
    file_type = "unknown"
    first_seen = "2026-08-22 00:27:24"
  condition:
    hash.sha256(0, filesize) == "27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213"
}
```

### Sample 45: `5af40e30ab869cd9`

| Field | Value |
|---|---|
| SHA-256 | `5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77` |
| Family label | `Mirai` |
| File name | `5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77.elf` |
| File type | `elf` |
| First seen | `2026-08-22 00:26:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a003b7f690768c3d11151bad0937dcd3` |
| SHA-1 | `d510b74681c12a6aadc9cc2ecf0eebe0ee5e1b00` |
| SHA-256 | `5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77` |
| SHA3-384 | `01e5d39699cf48054fd0e5af6f6b38c4b1a05a7e505329b850733768802d6ea84e18af37277344ecba78eb03f3069ea5` |
| TLSH | `T1D2633BD5BC406622C2C245B7FF0F424D7B1A4798E3D9334399286B71778BC9E0E6B646` |
| TELFHASH | `t117219db54e581edcaae28f4502ca321978a734b6fb0129254b5b7f8f0563ed1b51603a` |
| SSDEEP | `1536:44e/AO4uZ559YBSeUJvP4xxwOZoKwiLTefX:44eI5e59YIRJvuvwsTq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_5af40e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77"
    family = "Mirai"
    file_name = "5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77.elf"
    file_type = "elf"
    first_seen = "2026-08-22 00:26:03"
  condition:
    hash.sha256(0, filesize) == "5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77"
}
```

### Sample 46: `a157b86bb50b92c0`

| Field | Value |
|---|---|
| SHA-256 | `a157b86bb50b92c090fc69d53330f09f4e9cba5ad3f6d071cce6c541969d08be` |
| Family label | `Mirai` |
| File name | `bot.i686` |
| File type | `elf` |
| First seen | `2026-08-22 00:15:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c3d6aa1fdc02329b320207825f9fee7` |
| SHA-1 | `6d319fc6c052acfecea564130ca6535448697ec4` |
| SHA-256 | `a157b86bb50b92c090fc69d53330f09f4e9cba5ad3f6d071cce6c541969d08be` |
| SHA3-384 | `4d657f5124b21ce1600c3018c186cd8d39cf312e7e96ce8ec3c4d2b089fd42bc72bbb838f44f29081b96319d7f14e7e7` |
| TLSH | `T1DD633C80F58390F2D8131139906FB73FCA33D5698071DA99DF6A9F3AD9276027326399` |
| TELFHASH | `t16131f8f71dbe48f4b7e5a801c71e6f92186ad137256032e585b3cde026e39d29079c35` |
| SSDEEP | `768:v1W4b66fLHZYyh6598aSMYE6oHc+v1uTDuWzTahAJtG8lla9eq5M9TFTPLQn9wfm:v0YD5YKk8Sb8imyWeAVlxlFbLn+R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_a157b86b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a157b86bb50b92c090fc69d53330f09f4e9cba5ad3f6d071cce6c541969d08be"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-22 00:15:37"
  condition:
    hash.sha256(0, filesize) == "a157b86bb50b92c090fc69d53330f09f4e9cba5ad3f6d071cce6c541969d08be"
}
```

### Sample 47: `755b59727fa54b89`

| Field | Value |
|---|---|
| SHA-256 | `755b59727fa54b89a9e48fe04cc9004a63bfd43d8e55aefc25ce0c825ca6ab6c` |
| Family label | `ValleyRAT` |
| File name | `93BA6A64C60FD088B949BA9B17A6BF5A.dll` |
| File type | `dll` |
| First seen | `2026-08-22 00:15:15` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93ba6a64c60fd088b949ba9b17a6bf5a` |
| SHA-1 | `a53e11ab5cb43ff236905ac3702311f64cad5749` |
| SHA-256 | `755b59727fa54b89a9e48fe04cc9004a63bfd43d8e55aefc25ce0c825ca6ab6c` |
| SHA3-384 | `2630a674dee3d598fda6d3d51b58682441811fa425465382d28a40c972e0e5d3a9b1d3f9da27008bdbd8c16c65318ddc` |
| IMPHASH | `ded26d33ae9a6077eea99e272c4c8255` |
| TLSH | `T13F56D0313D5D009EE0AA12398F68AAEDF2FE7DA03BB531571980F639FB35B414A1415B` |
| SSDEEP | `98304:g2C7uzfNvxse6NjjsAI+jEqkKmHVpXFxr5n6fyq+nkDOByQfoOiGBx5A2NwKEYos:lV9GAqkKmHVpXFxr5n6fyq+nkDOByQf3` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_047_755b5972
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "755b59727fa54b89a9e48fe04cc9004a63bfd43d8e55aefc25ce0c825ca6ab6c"
    family = "ValleyRAT"
    file_name = "93BA6A64C60FD088B949BA9B17A6BF5A.dll"
    file_type = "dll"
    first_seen = "2026-08-22 00:15:15"
  condition:
    hash.sha256(0, filesize) == "755b59727fa54b89a9e48fe04cc9004a63bfd43d8e55aefc25ce0c825ca6ab6c"
}
```

### Sample 48: `18667c138b756654`

| Field | Value |
|---|---|
| SHA-256 | `18667c138b756654501dc2d742285f9795a76209ba3565d07ed6cf11798d3308` |
| Family label | `RemusStealer` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:15:08` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `951f71e07fd49bcd48e8ca76c9c26251` |
| SHA-1 | `1a55bf701fba1ded6e25ee5770e70c02fcc85135` |
| SHA-256 | `18667c138b756654501dc2d742285f9795a76209ba3565d07ed6cf11798d3308` |
| SHA3-384 | `b8ac905739cfbcc86ef3c5fb18be11c12a56349006389ee09152beaaf1b2da7d27f7fed49ad372adeff185bbb343f8d1` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1B9562713799541E5C4AADB34C47782137A60F88DEB3923935E21AE342F757C2ADBBB04` |
| SSDEEP | `49152:r8J52apuqee339iAhk0nunqVR5gZWIb6A44D:AzuuoWvq` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_048_18667c13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18667c138b756654501dc2d742285f9795a76209ba3565d07ed6cf11798d3308"
    family = "RemusStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:15:08"
  condition:
    hash.sha256(0, filesize) == "18667c138b756654501dc2d742285f9795a76209ba3565d07ed6cf11798d3308"
}
```

### Sample 49: `c77dc176b6b643e8`

| Field | Value |
|---|---|
| SHA-256 | `c77dc176b6b643e833ce40829cfbc783b7a0ec317ec12e35095e6523dfb73d8a` |
| Family label | `SnappyClient` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:13:59` |
| Reporter | `iamaachum` |
| Tags | `exe, HijackLoader, SnappyClient, Vidar, YodaTeam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1467f5f92f91eb363cfaf1c902ffb0a2` |
| SHA-1 | `4ef9c4468fd4f3ac58a083393e64dcc093ebb3c2` |
| SHA-256 | `c77dc176b6b643e833ce40829cfbc783b7a0ec317ec12e35095e6523dfb73d8a` |
| SHA3-384 | `363c94b793ebe52e41abf535b96372758293ba93c2b25dd9740b58bcceff5456e10cb5ae00e4b129dc14efe0ccf1274b` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T161A633533B46A4F1E02A9A316FC7DB0702B7C77D1615CE7B61921ECEACA30A11A475CE` |
| SSDEEP | `196608:+ppHDvWq069kN6ncZi1UGS4M4RoLEvL10dshbJC7X9V0IvTahm8x:+pp2GK6cb0MNL+p0oy91vWhNx` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_049_c77dc176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c77dc176b6b643e833ce40829cfbc783b7a0ec317ec12e35095e6523dfb73d8a"
    family = "SnappyClient"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:13:59"
  condition:
    hash.sha256(0, filesize) == "c77dc176b6b643e833ce40829cfbc783b7a0ec317ec12e35095e6523dfb73d8a"
}
```

### Sample 50: `a72bef4260809754`

| Field | Value |
|---|---|
| SHA-256 | `a72bef426080975468dc686c7bc44cc99d3574ab626382632921dc48366cf107` |
| Family label | `Mirai` |
| File name | `bot.sh4` |
| File type | `elf` |
| First seen | `2026-08-22 00:13:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40766da228582ae869dc6664488d956d` |
| SHA-1 | `59388c12212fec12d5fc6d947ef1d5fe865a6cd6` |
| SHA-256 | `a72bef426080975468dc686c7bc44cc99d3574ab626382632921dc48366cf107` |
| SHA3-384 | `c6f060064ba86ec5bb4e37c70a7afec73f71c3b909c2f2668bfc6fc87f4983d667e22e15c83822d1c9793f445d84f3b1` |
| TLSH | `T1C0537B62CA713D19E02446B17560CE309B67E50582CB2EFEAA64C36DD407EDEF2697F0` |
| SSDEEP | `1536:efyI8bF3No9HjJKDct+fNVVmdVx70CHOjb:PbF9o9HjwDtzVmdVx70zb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_a72bef42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a72bef426080975468dc686c7bc44cc99d3574ab626382632921dc48366cf107"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-08-22 00:13:36"
  condition:
    hash.sha256(0, filesize) == "a72bef426080975468dc686c7bc44cc99d3574ab626382632921dc48366cf107"
}
```

### Sample 51: `3924cc20aef6c286`

| Field | Value |
|---|---|
| SHA-256 | `3924cc20aef6c2864187f4d5f942056b1f2ac33ab66af6e0ce0985701a3ea091` |
| Family label | `SnappyClient` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:11:32` |
| Reporter | `iamaachum` |
| Tags | `exe, HijackLoader, SnappyClient, Vidar, YodaTeam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cdd492f8bf92e342c2671c79baf274d` |
| SHA-1 | `afcd955f27c3d919c33ce6e9bd76e03ef69f6d18` |
| SHA-256 | `3924cc20aef6c2864187f4d5f942056b1f2ac33ab66af6e0ce0985701a3ea091` |
| SHA3-384 | `0f9632911354a5fd84e657d6624daea969b178d22d23da1670d214e51143939a80a0eeb67c8cc363c87803e7e4b0f2fd` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T125B63303B71CA8F1E969C8B23F07C3112D77E7DB91465E4B419E0E6A1CA71AA1247DCE` |
| SSDEEP | `196608:+p7qxlODKcTIEGlQq3khEnh9l+0qlpQg9SkLKAIvTahm8u:+p7qrODKFEMQ/kh9l+0qIg4kWPvWhNu` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_051_3924cc20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3924cc20aef6c2864187f4d5f942056b1f2ac33ab66af6e0ce0985701a3ea091"
    family = "SnappyClient"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:11:32"
  condition:
    hash.sha256(0, filesize) == "3924cc20aef6c2864187f4d5f942056b1f2ac33ab66af6e0ce0985701a3ea091"
}
```

### Sample 52: `90cd82d7296ca7b1`

| Field | Value |
|---|---|
| SHA-256 | `90cd82d7296ca7b11480d47e6e7d94bd69d586a942d39ae8c899bf5df083c46a` |
| Family label | `unknown` |
| File name | `FLStudio2025_v158_Win.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:09:32` |
| Reporter | `iamaachum` |
| Tags | `exe, Stealc, svhost-update-service-casa` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93d766dd78be7c3f2a54af0605c89014` |
| SHA-1 | `45fe16ae9f2d825714581ecc691741bd06ef2cfb` |
| SHA-256 | `90cd82d7296ca7b11480d47e6e7d94bd69d586a942d39ae8c899bf5df083c46a` |
| SHA3-384 | `641d08ed354b39ed22683137a72c0b908d349b42bdf3172a479d0cfdf010682df07ba4bf9db431760556281ae3d1e778` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13F552358222BC827D462ABB35AC2D07003708D59F413D257AFDA3DDF7625B9A4EE0793` |
| SSDEEP | `24576:I0mcZSTTfBg1p3AT0/jYg7B07HcYeeMuy2fCTFfar4K9pCRmLBBElijf0rtVy:ic8TTfBMwT0bYgi7HcjeXygCFE9p4mLJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_90cd82d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90cd82d7296ca7b11480d47e6e7d94bd69d586a942d39ae8c899bf5df083c46a"
    family = "unknown"
    file_name = "FLStudio2025_v158_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:09:32"
  condition:
    hash.sha256(0, filesize) == "90cd82d7296ca7b11480d47e6e7d94bd69d586a942d39ae8c899bf5df083c46a"
}
```

### Sample 53: `a3c7d47493c861c2`

| Field | Value |
|---|---|
| SHA-256 | `a3c7d47493c861c2cdfe687144fc2a207cf1d10fd1b98c635746f76b8ebe8093` |
| Family label | `RemusStealer` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:08:42` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, windowsof-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6382cc926c12e770b027b29b23a724d1` |
| SHA-1 | `0084efdf29628ef0e6991200dda6a652f5088c29` |
| SHA-256 | `a3c7d47493c861c2cdfe687144fc2a207cf1d10fd1b98c635746f76b8ebe8093` |
| SHA3-384 | `de57ee923d6ad0f58b3238f18ddaa8596333ec9a9c0eb13f256177d3f330e5c0fb5a7f734ec5e471a08beac69c1b17b1` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T164563913799541E4C4AADE34C47382137A24F88DDB3533A35E61BA342FB57C2ADBAB44` |
| SSDEEP | `49152:t59V3ITLqki+5P+Cn2mRpASqj0mpRlmR3OZB9S8:B88dF` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_053_a3c7d474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c7d47493c861c2cdfe687144fc2a207cf1d10fd1b98c635746f76b8ebe8093"
    family = "RemusStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:08:42"
  condition:
    hash.sha256(0, filesize) == "a3c7d47493c861c2cdfe687144fc2a207cf1d10fd1b98c635746f76b8ebe8093"
}
```

### Sample 54: `641fcc308925f037`

| Field | Value |
|---|---|
| SHA-256 | `641fcc308925f0376adb2c30cdf7aa6710c0d227bfc4491fc803cc3efcf4941f` |
| Family label | `RemusStealer` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:07:45` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7daba441fc2dd8ea0a384d3d0c9c016d` |
| SHA-1 | `8c75e2a3b40f6ab1cc796919d38f3aa2b534b93f` |
| SHA-256 | `641fcc308925f0376adb2c30cdf7aa6710c0d227bfc4491fc803cc3efcf4941f` |
| SHA3-384 | `9f8bce2c9f5dacb1beeda12dc7ffc1e1180d21d5ee20942585f11ea3790ea443d24b6569811a8bc512d7e7dcd96b1f09` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T166364A03BDA545A9C0AAA734C9B78752BB75BC88873133D72E50AA383F72BD06D75704` |
| SSDEEP | `24576:/1S51yKWlCONgvVyG2lNzmEBXdPxZadICwCufU26MQH1PjvAdTOOWrHgMUhyqImc:RKWlLoV8tBXdPxZQICs81Zrg7Tm0e` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_054_641fcc30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "641fcc308925f0376adb2c30cdf7aa6710c0d227bfc4491fc803cc3efcf4941f"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:07:45"
  condition:
    hash.sha256(0, filesize) == "641fcc308925f0376adb2c30cdf7aa6710c0d227bfc4491fc803cc3efcf4941f"
}
```

### Sample 55: `974db02465535976`

| Field | Value |
|---|---|
| SHA-256 | `974db0246553597676603c5aafa7b1a855dc6bdbbe657d0036470dee1cbc3fea` |
| Family label | `unknown` |
| File name | `libvlc.dll` |
| File type | `exe` |
| First seen | `2026-08-22 00:06:37` |
| Reporter | `UnknownSilicon` |
| Tags | `exe, purelogsstealer, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad7ff919835856e09be4c41d0d683bdb` |
| SHA-1 | `7ec7d2510f586ce872d7b370c9bcd38f2ae7d29c` |
| SHA-256 | `974db0246553597676603c5aafa7b1a855dc6bdbbe657d0036470dee1cbc3fea` |
| SHA3-384 | `f29d452dd1f3c11ee4965c7a8be03e7119106eb92119a81853da20924ddacb7b4d5aa6f65d85f3de5e817560841ac083` |
| IMPHASH | `8fce492d90b6ed296f73daae11f6975f` |
| TLSH | `T1FA85B1A82ED025F4E2B4CD75DB6BB6B4537F362F2D436BB7022092603B7315A9A43C15` |
| SSDEEP | `49152:3s70mgO4AYjC6/qnrB7ufxg/k4ybtq3cXkeVqqvJjkIRK:9AYj7qnrBafC/+btHXkeVqqRjkIRK` |
| ICON-DHASH | `a6a9a6a9a2a9a6a9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_974db024
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "974db0246553597676603c5aafa7b1a855dc6bdbbe657d0036470dee1cbc3fea"
    family = "unknown"
    file_name = "libvlc.dll"
    file_type = "exe"
    first_seen = "2026-08-22 00:06:37"
  condition:
    hash.sha256(0, filesize) == "974db0246553597676603c5aafa7b1a855dc6bdbbe657d0036470dee1cbc3fea"
}
```

### Sample 56: `82085936272bf263`

| Field | Value |
|---|---|
| SHA-256 | `82085936272bf263f09cb82c1d9d94c6098f5c46a973d00da4c682346e3fa71e` |
| Family label | `unknown` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-08-22 00:06:34` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, cdn-falconworks-cc, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d252e8f0884cdfd7a81c26f2009b7719` |
| SHA-1 | `26a0fda22f954435e12528f1b270ff8e046692d0` |
| SHA-256 | `82085936272bf263f09cb82c1d9d94c6098f5c46a973d00da4c682346e3fa71e` |
| SHA3-384 | `005f996aa57c9b25f7582d5a40558344488e343201ee52ced4da02d10f8da5ee4980764dd94381054c30b0ddf7b709e5` |
| IMPHASH | `682698ea78be8d2edcfadd8b96c3e30b` |
| TLSH | `T173950251E6C381F2DE435836366EF32F5B225A068C31DBDEE7E86D4A68A3740265F1C1` |
| SSDEEP | `24576:i3TWgO5pPZCTGkE9MMXxoq6+MNluBDIHSDIS7u9vFOy7apBxFmgdErvWiYyjMtWe:hgT7q72H/S7UvSjD6rvWiYyjM4SEXo3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_82085936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82085936272bf263f09cb82c1d9d94c6098f5c46a973d00da4c682346e3fa71e"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:06:34"
  condition:
    hash.sha256(0, filesize) == "82085936272bf263f09cb82c1d9d94c6098f5c46a973d00da4c682346e3fa71e"
}
```

### Sample 57: `f80ea3ce4bb1bcf1`

| Field | Value |
|---|---|
| SHA-256 | `f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043` |
| Family label | `unknown` |
| File name | `f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043` |
| File type | `unknown` |
| First seen | `2026-08-22 00:00:45` |
| Reporter | `anonymous` |
| Tags | `cowrie, hermes-noc, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a4dd348f4d793783f11154f31abf75e` |
| SHA-256 | `f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_f80ea3ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043"
    family = "unknown"
    file_name = "f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043"
    file_type = "unknown"
    first_seen = "2026-08-22 00:00:45"
  condition:
    hash.sha256(0, filesize) == "f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043"
}
```

### Sample 58: `b6db146a4318ab09`

| Field | Value |
|---|---|
| SHA-256 | `b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866` |
| Family label | `unknown` |
| File name | `b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866` |
| File type | `sh` |
| First seen | `2026-08-21 23:57:33` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `767fcd6b4d3afc73d5225cf8c2b5fc65` |
| SHA-1 | `7ca92213e53219abe86ef5c498fe9065c81806b6` |
| SHA-256 | `b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866` |
| SHA3-384 | `7c885ff44df4ee4cc36edeb2d8c6a40b42dec5573a9bc0d7b4e7463ae67dad0c4b01703e51a8626a94d9aebce012a603` |
| TLSH | `T194F09EA6B838EB32F70E884857768CE929012AAB081E09503083CE55265C2B1226B210` |
| SSDEEP | `12:xLNbuPFn4u7q8Mr0POdiw55SFFedSQm9EAE3:PKP+u7q89WdiweF/9Ex3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_b6db146a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866"
    family = "unknown"
    file_name = "b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866"
    file_type = "sh"
    first_seen = "2026-08-21 23:57:33"
  condition:
    hash.sha256(0, filesize) == "b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866"
}
```

### Sample 59: `fd61ded6fdcedc06`

| Field | Value |
|---|---|
| SHA-256 | `fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5` |
| Family label | `unknown` |
| File name | `fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5` |
| File type | `sh` |
| First seen | `2026-08-21 23:57:31` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c76d76427793b954e30c564d80cf51e` |
| SHA-1 | `0d0f38ef890a670507d2cefeca812282c99f190e` |
| SHA-256 | `fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5` |
| SHA3-384 | `73b3ca1413d37e1e80c6941063cb41c05abe5a5836fcc7688350a18b2ee1e30e68b71120ab8834b7b102f095cab06d95` |
| TLSH | `T1F2D02BE663216533721E4049335558E4120901EF8CAFC874304F4DB03B4D704FA6D116` |
| SSDEEP | `6:Px9Kqp6e2cqFUo9Kqp6e2cvgr158sLdNnLI:PqqUJFUDqUKoPhM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_fd61ded6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5"
    family = "unknown"
    file_name = "fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5"
    file_type = "sh"
    first_seen = "2026-08-21 23:57:31"
  condition:
    hash.sha256(0, filesize) == "fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5"
}
```

### Sample 60: `ea5b8411ef37ad40`

| Field | Value |
|---|---|
| SHA-256 | `ea5b8411ef37ad40486c019c674565392e10cef6700c707f81284adebcdc157f` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-21 23:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31ce2c2db7eb2bf68796239e635d08a3` |
| SHA-256 | `ea5b8411ef37ad40486c019c674565392e10cef6700c707f81284adebcdc157f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_ea5b8411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5b8411ef37ad40486c019c674565392e10cef6700c707f81284adebcdc157f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 23:52:13"
  condition:
    hash.sha256(0, filesize) == "ea5b8411ef37ad40486c019c674565392e10cef6700c707f81284adebcdc157f"
}
```

### Sample 61: `d5aea22bf23f26d0`

| Field | Value |
|---|---|
| SHA-256 | `d5aea22bf23f26d0c83d5d96f46f16a4207b69a37956ce975c1b7b2351fcc5cf` |
| Family label | `DCRat` |
| File name | `734F2038EDC0FB655E13004199F9E7DA.exe` |
| File type | `exe` |
| First seen | `2026-08-21 23:50:07` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `734f2038edc0fb655e13004199f9e7da` |
| SHA-1 | `ebdf31eea680b4e3db0265e1bc9d99e1236674e8` |
| SHA-256 | `d5aea22bf23f26d0c83d5d96f46f16a4207b69a37956ce975c1b7b2351fcc5cf` |
| SHA3-384 | `b56c9a2e0c1142c34072f36cc2d826ae5f16f0cbb70dba1bf1f272c2c0757ab62b5e4c887fffe9909bd2c64d65c1abb9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19E06F10A95924F3BC26097358497443E53A4C7767962FB0B3A1F11D26C037B9DFB22AB` |
| SSDEEP | `49152:WLZoXeXCFaONlGzCdGTGAXD2vO6cOJyLuAcLKzAa9oU7Tc4:WGuXAlGGdGTGAXD2vbXaN5` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_061_d5aea22b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5aea22bf23f26d0c83d5d96f46f16a4207b69a37956ce975c1b7b2351fcc5cf"
    family = "DCRat"
    file_name = "734F2038EDC0FB655E13004199F9E7DA.exe"
    file_type = "exe"
    first_seen = "2026-08-21 23:50:07"
  condition:
    hash.sha256(0, filesize) == "d5aea22bf23f26d0c83d5d96f46f16a4207b69a37956ce975c1b7b2351fcc5cf"
}
```

### Sample 62: `768a14a6c0c4f8ea`

| Field | Value |
|---|---|
| SHA-256 | `768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7` |
| Family label | `unknown` |
| File name | `768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7.exe` |
| File type | `exe` |
| First seen | `2026-08-21 23:46:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1c0271fb95baf0b83ec7c2d55c354b7` |
| SHA-1 | `87ebc061d0d9a94559ce39fe1b4d9f78d350bb65` |
| SHA-256 | `768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7` |
| SHA3-384 | `52e172adf7318defb93653f2ce467cd2143800aa8c5af489456e8499fd4e8d11f792cba421a5cdbb2e9d4c1db725f94b` |
| IMPHASH | `b8048b8957358587b4fda264349e8f60` |
| TLSH | `T11CD5238AB1FA18B1C8F3C7B2EF02F02D716973D14A708D9B75CD6A018D42568AD36376` |
| SSDEEP | `49152:ntJ5+BgfufmYWYKEzlV/3qQqZUFDbRSe7GE8XzJEeJfWbVagevRbYr6WdCY:tgmY6YOURSeCE8XzJDlwVRQRbj/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_768a14a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7"
    family = "unknown"
    file_name = "768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7.exe"
    file_type = "exe"
    first_seen = "2026-08-21 23:46:17"
  condition:
    hash.sha256(0, filesize) == "768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7"
}
```

### Sample 63: `086f204a2f6f84c2`

| Field | Value |
|---|---|
| SHA-256 | `086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5` |
| Family label | `unknown` |
| File name | `086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5` |
| File type | `sh` |
| First seen | `2026-08-21 23:29:46` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e59c75818142afa55b595fcda08f0612` |
| SHA-1 | `ed1316796e51a518566ea5ea8f55d98751c752b9` |
| SHA-256 | `086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5` |
| SHA3-384 | `5b052d6d740c8a97224cac27d0d61a5b0313defb6ccd53558a2a33c8f36e0d6ef80c5dea1ffec9f3f7f7b3bbacc64cf7` |
| TLSH | `T135B0128010A028F3F2056B43310C815417C400D01406397C78210F7050B6700FE02380` |
| SSDEEP | `3:TKH/3LIWFHCLfXlKqtfT6dyVRIVbtaFOdX/bv:mrFHI9Kqp6oU5aQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_086f204a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5"
    family = "unknown"
    file_name = "086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5"
    file_type = "sh"
    first_seen = "2026-08-21 23:29:46"
  condition:
    hash.sha256(0, filesize) == "086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5"
}
```

### Sample 64: `98cbbf4ceb2d1281`

| Field | Value |
|---|---|
| SHA-256 | `98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5` |
| Family label | `unknown` |
| File name | `98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5` |
| File type | `unknown` |
| First seen | `2026-08-21 23:21:00` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `703cfbe518c45eea2617025ba35eec85` |
| SHA-256 | `98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_98cbbf4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5"
    family = "unknown"
    file_name = "98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5"
    file_type = "unknown"
    first_seen = "2026-08-21 23:21:00"
  condition:
    hash.sha256(0, filesize) == "98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5"
}
```

### Sample 65: `e668d8fcccd5362e`

| Field | Value |
|---|---|
| SHA-256 | `e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd` |
| Family label | `unknown` |
| File name | `e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd` |
| File type | `unknown` |
| First seen | `2026-08-21 23:20:59` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87654be3351f44206f281a6744ed89e8` |
| SHA-256 | `e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_e668d8fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd"
    family = "unknown"
    file_name = "e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd"
    file_type = "unknown"
    first_seen = "2026-08-21 23:20:59"
  condition:
    hash.sha256(0, filesize) == "e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd"
}
```

### Sample 66: `9420e279446ceec7`

| Field | Value |
|---|---|
| SHA-256 | `9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a` |
| Family label | `unknown` |
| File name | `9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a` |
| File type | `unknown` |
| First seen | `2026-08-21 23:20:57` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `143ea4fdacb4b24ebb922b261beb9b83` |
| SHA-256 | `9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_9420e279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a"
    family = "unknown"
    file_name = "9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a"
    file_type = "unknown"
    first_seen = "2026-08-21 23:20:57"
  condition:
    hash.sha256(0, filesize) == "9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a"
}
```

### Sample 67: `d96c6de7ab6abc18`

| Field | Value |
|---|---|
| SHA-256 | `d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5` |
| Family label | `unknown` |
| File name | `d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5` |
| File type | `sh` |
| First seen | `2026-08-21 23:20:56` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `587c74c8512d397be9d66bc938d0279a` |
| SHA-1 | `ee38c13ce93bf02b67d3a7513e1b8e260a5cf477` |
| SHA-256 | `d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5` |
| SHA3-384 | `afb324bae9aa310e5574003504ecbbc710ec01e57663c90800f57e444a58e2041472963ab26873ee1d43063e9f7031bc` |
| TLSH | `T1A59133A3F8B0E4727F8F803D6B7F99583902165B09187D18B44F7C142F5C25D72BAA2A` |
| SSDEEP | `48:EuYRIpEojTlzVl58VBjHvtroEunuSozHIz0rfaOg7aOalol3Jq48vYX8zoZ4ogV1:jwVJzcel8IJYb4zrMbbPwg8mM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_d96c6de7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5"
    family = "unknown"
    file_name = "d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5"
    file_type = "sh"
    first_seen = "2026-08-21 23:20:56"
  condition:
    hash.sha256(0, filesize) == "d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5"
}
```

### Sample 68: `f42c77fc05af60b8`

| Field | Value |
|---|---|
| SHA-256 | `f42c77fc05af60b8e702ab357714890d2ce17419d63bcc108f00be7733e8c7c5` |
| Family label | `ValleyRAT` |
| File name | `480F7E5181F67F318948AE9D304BC06F.dll` |
| File type | `dll` |
| First seen | `2026-08-21 23:10:16` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `480f7e5181f67f318948ae9d304bc06f` |
| SHA-1 | `8b0f970d3a3b51fa167d99d4fe0d4472187fdad3` |
| SHA-256 | `f42c77fc05af60b8e702ab357714890d2ce17419d63bcc108f00be7733e8c7c5` |
| SHA3-384 | `57cf649118975f452688d5bc854a5430879f3af0acc8f577eefaa8ea9e9e77a773b946cd9b034552a18d3f729060c205` |
| IMPHASH | `31b6b8efbaf931b2106dbb036151cf7b` |
| TLSH | `T18A56D0913D5C40A6E05B1231CF6BA2BCF2EE7DB03B75315B1680FA1AFB357414A18A5B` |
| SSDEEP | `98304:c6CysmjOw4YDZJdbYM6ZahkmVnrSbVHyqbtbZ4OiZrq1DfPHNADtV6v+zM+rwroJ:Bs7wnBP6Zahkmxi1RZ4O7NADtV6v+zZT` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_068_f42c77fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42c77fc05af60b8e702ab357714890d2ce17419d63bcc108f00be7733e8c7c5"
    family = "ValleyRAT"
    file_name = "480F7E5181F67F318948AE9D304BC06F.dll"
    file_type = "dll"
    first_seen = "2026-08-21 23:10:16"
  condition:
    hash.sha256(0, filesize) == "f42c77fc05af60b8e702ab357714890d2ce17419d63bcc108f00be7733e8c7c5"
}
```

### Sample 69: `466bb2599b3522d0`

| Field | Value |
|---|---|
| SHA-256 | `466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3` |
| Family label | `unknown` |
| File name | `466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3` |
| File type | `sh` |
| First seen | `2026-08-21 23:00:18` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c0cb196c350210fb0e9483c27f1b256` |
| SHA-1 | `062eeb763fe28b018fb213782011aca5a0a9acc9` |
| SHA-256 | `466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3` |
| SHA3-384 | `ad060a91c9351b8e1e748fb2a0c49802dd58cd790c88673c48984ae789f8e278387cf1ade66e74d1a10450dacb177d42` |
| TLSH | `T15831C1EF142419311002CD8D33A67948B28DA6E77D4FD7E1D9091EF9864C2CCF2A2B8A` |
| SSDEEP | `24:zps97jTaj5igE/6vwhUh4g0I0IICgD0MDSu:Njwt/6oI/bC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_466bb259
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3"
    family = "unknown"
    file_name = "466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3"
    file_type = "sh"
    first_seen = "2026-08-21 23:00:18"
  condition:
    hash.sha256(0, filesize) == "466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3"
}
```

### Sample 70: `d7437869437f3b95`

| Field | Value |
|---|---|
| SHA-256 | `d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41` |
| Family label | `unknown` |
| File name | `d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41` |
| File type | `sh` |
| First seen | `2026-08-21 22:57:45` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5063b23ab1c3317776d765973e821d23` |
| SHA-1 | `22a715873d214d630a5a89ad57e2dd28160ea208` |
| SHA-256 | `d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41` |
| SHA3-384 | `9806396090321e2ac091a191fb6ec16bfbd312a58ad6a6b77b86ee55f9bf4cfb0dd8c0722dd2efcc3ba961a3b29fbc83` |
| TLSH | `T1CA71A6827871A433A20F417E5B5BAC543543166F1428BC44B58FBC181F6C7E99269D79` |
| SSDEEP | `48:86RkNcIpEojTlzVl58jHvtroEj1nulozHIF01jQsTg7QsTQLfbTHpI8l3EZ8l3l1:86emZw2zJMbIf/e8l3q8l3lA5lK8VK1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_d7437869
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41"
    family = "unknown"
    file_name = "d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41"
    file_type = "sh"
    first_seen = "2026-08-21 22:57:45"
  condition:
    hash.sha256(0, filesize) == "d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41"
}
```

### Sample 71: `b3b4992027e7e699`

| Field | Value |
|---|---|
| SHA-256 | `b3b4992027e7e6999f891d0152b1e86e986f4518397696a2bc189d21ab78f018` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-21 22:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94f8910ef299c8a91dc4b2445891d1dd` |
| SHA-256 | `b3b4992027e7e6999f891d0152b1e86e986f4518397696a2bc189d21ab78f018` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_b3b49920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3b4992027e7e6999f891d0152b1e86e986f4518397696a2bc189d21ab78f018"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 22:52:11"
  condition:
    hash.sha256(0, filesize) == "b3b4992027e7e6999f891d0152b1e86e986f4518397696a2bc189d21ab78f018"
}
```

### Sample 72: `74e6459121f80d5c`

| Field | Value |
|---|---|
| SHA-256 | `74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c` |
| Family label | `unknown` |
| File name | `74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c` |
| File type | `unknown` |
| First seen | `2026-08-21 22:27:02` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7d4e2501a5ec1540753285ed74f6ef9` |
| SHA-256 | `74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_74e64591
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c"
    family = "unknown"
    file_name = "74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c"
    file_type = "unknown"
    first_seen = "2026-08-21 22:27:02"
  condition:
    hash.sha256(0, filesize) == "74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c"
}
```

### Sample 73: `15c1d1f3ac0418a3`

| Field | Value |
|---|---|
| SHA-256 | `15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765` |
| Family label | `unknown` |
| File name | `15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765` |
| File type | `sh` |
| First seen | `2026-08-21 22:27:00` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `434ae0d8bdb4c635563ebf1fc37bc1bc` |
| SHA-1 | `919e512c33ced0629a01417c36d71903bd2f10c0` |
| SHA-256 | `15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765` |
| SHA3-384 | `b4ac14d2ebc7cd617d24b9c44ba7a0a7da64cf88f3c307d1e074101946ed755d44ee055f6ad19467a7f9186f63f7bef6` |
| TLSH | `T16FC162017490E5705E4E8C3E4A76DC106501210FFC05AD28F68FA8E0AF78B99FEF95AA` |
| SSDEEP | `96:dOHwZwZDehKAL3iWd/9lx8lJlWWRzOBE/ZifWCv:dOxZKzLSUPxSlW0zOBEQWK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_15c1d1f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765"
    family = "unknown"
    file_name = "15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765"
    file_type = "sh"
    first_seen = "2026-08-21 22:27:00"
  condition:
    hash.sha256(0, filesize) == "15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765"
}
```

### Sample 74: `06bcf8b6ba6a3cf0`

| Field | Value |
|---|---|
| SHA-256 | `06bcf8b6ba6a3cf02571bb94c135453b70a76fdd6e5ecf55f9fd384efaa8e308` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 22:22:17` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82ce3bf7e2dc8c1dea6ff1e2a7e4d8de` |
| SHA-1 | `db895303f8ae14c4d726aa07c9a8f6738d03e1a9` |
| SHA-256 | `06bcf8b6ba6a3cf02571bb94c135453b70a76fdd6e5ecf55f9fd384efaa8e308` |
| SHA3-384 | `572248bafecbe1373a7190d77846b890de857d55e313d7075cee55cdf8db2dba39b58f5f3908e4d040af5cde44965a8a` |
| IMPHASH | `62680188ed52e353b48aab23a1b19fd9` |
| TLSH | `T126F59E48F71F7872EC6FE87158CBAF8D0124576589723EDC07062F112F1B269A2668BD` |
| SSDEEP | `24576:XuAzVzdrpr/gfG3MZgP1mz8FU/elwy1C8n7FXrVoXQv1mROUM3yJUK8norkP2zk5:+AqGI5sw8rf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_06bcf8b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06bcf8b6ba6a3cf02571bb94c135453b70a76fdd6e5ecf55f9fd384efaa8e308"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 22:22:17"
  condition:
    hash.sha256(0, filesize) == "06bcf8b6ba6a3cf02571bb94c135453b70a76fdd6e5ecf55f9fd384efaa8e308"
}
```

### Sample 75: `f054b071032e81ea`

| Field | Value |
|---|---|
| SHA-256 | `f054b071032e81ea59a4ecfbbaa8e8fd080bca0a9ad50c44b9c9772172de7bf5` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-21 21:52:12` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5066dc447a12a674fefc5f28c9027e7` |
| SHA-256 | `f054b071032e81ea59a4ecfbbaa8e8fd080bca0a9ad50c44b9c9772172de7bf5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_f054b071
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f054b071032e81ea59a4ecfbbaa8e8fd080bca0a9ad50c44b9c9772172de7bf5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 21:52:12"
  condition:
    hash.sha256(0, filesize) == "f054b071032e81ea59a4ecfbbaa8e8fd080bca0a9ad50c44b9c9772172de7bf5"
}
```

### Sample 76: `d8df49c39fc031f2`

| Field | Value |
|---|---|
| SHA-256 | `d8df49c39fc031f2f460f2bd632c43ac8c8f2aa27ca319ecd9ff259e2eca3768` |
| Family label | `unknown` |
| File name | `stego_jxdqj7fw9j.png` |
| File type | `unknown` |
| First seen | `2026-08-21 21:51:48` |
| Reporter | `anonymous` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2028b560f347823542042979e4e82b11` |
| SHA-256 | `d8df49c39fc031f2f460f2bd632c43ac8c8f2aa27ca319ecd9ff259e2eca3768` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_d8df49c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8df49c39fc031f2f460f2bd632c43ac8c8f2aa27ca319ecd9ff259e2eca3768"
    family = "unknown"
    file_name = "stego_jxdqj7fw9j.png"
    file_type = "unknown"
    first_seen = "2026-08-21 21:51:48"
  condition:
    hash.sha256(0, filesize) == "d8df49c39fc031f2f460f2bd632c43ac8c8f2aa27ca319ecd9ff259e2eca3768"
}
```

### Sample 77: `dc7153a7ed6e0c96`

| Field | Value |
|---|---|
| SHA-256 | `dc7153a7ed6e0c9666de705d53416c62eda0d0c879d6da9a108e282c529cebef` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 21:51:31` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `191f72fca602289760b880eb9d573959` |
| SHA-1 | `d166d2bdc14d2a6568eebff10c0d673f603843bc` |
| SHA-256 | `dc7153a7ed6e0c9666de705d53416c62eda0d0c879d6da9a108e282c529cebef` |
| SHA3-384 | `8545753d65e3abf114d8df8c29072b9b7fcc69eded5865fb15586fd786e3f86a8faf2dc21b8ccc09f6b193bdf2c0a46a` |
| TLSH | `T152541257C1F11D64C2E296F461A8C641B4B7B809AB9802FF7B81891E3D57FC18B72F05` |
| SSDEEP | `6144:IXhDVs6rFnguZTPlNKbyM1Z1klgVeAUSOtlHhHEzO:IX3sUFnguNlNKbH/2lgV1U7ZhkzO` |
| ICON-DHASH | `eae2cad4fcf4d2ca` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_dc7153a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc7153a7ed6e0c9666de705d53416c62eda0d0c879d6da9a108e282c529cebef"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:51:31"
  condition:
    hash.sha256(0, filesize) == "dc7153a7ed6e0c9666de705d53416c62eda0d0c879d6da9a108e282c529cebef"
}
```

### Sample 78: `fba265611c94bd8c`

| Field | Value |
|---|---|
| SHA-256 | `fba265611c94bd8ce572991abe3437786c7b2b1d8da78dc3e8a825787b3d5a27` |
| Family label | `unknown` |
| File name | `PO 100626-26NB005 086 246-2 254 -ZOLANO,Stokes,Woolworth-SHANTOU-FULL.DEP.BAL- $51,496.86.js` |
| File type | `js` |
| First seen | `2026-08-21 21:47:46` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `917a25261468aafd531815d1991f0865` |
| SHA-1 | `74a1b8cbe244bacc93f048a10bb6a0100520c2eb` |
| SHA-256 | `fba265611c94bd8ce572991abe3437786c7b2b1d8da78dc3e8a825787b3d5a27` |
| SHA3-384 | `1e724da86331214fa03544d85e0ce8be960fcc12a9ff240fd37e2caad84c75f92ddc00d4c6a3106665f482067a03ede0` |
| TLSH | `T121050C7782BE2F2AC8275A59CEB93C0C9CF054A20B4EF479ED3764C5E47CBD966A0150` |
| SSDEEP | `192:uL4tuc/eP3NTps7nrZKD2VvGppS+8qe39/FKjfOo3HE/W2f6BLpfFlz7jizzd857:g` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_fba26561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba265611c94bd8ce572991abe3437786c7b2b1d8da78dc3e8a825787b3d5a27"
    family = "unknown"
    file_name = "PO 100626-26NB005 086 246-2 254 -ZOLANO,Stokes,Woolworth-SHANTOU-FULL.DEP.BAL- $51,496.86.js"
    file_type = "js"
    first_seen = "2026-08-21 21:47:46"
  condition:
    hash.sha256(0, filesize) == "fba265611c94bd8ce572991abe3437786c7b2b1d8da78dc3e8a825787b3d5a27"
}
```

### Sample 79: `563512cbc00ac478`

| Field | Value |
|---|---|
| SHA-256 | `563512cbc00ac478207d204bf4fd686a533cfa7d8a3948c6d7ba94fb08716fa1` |
| Family label | `Mirai` |
| File name | `dlr.mips` |
| File type | `elf` |
| First seen | `2026-08-21 21:42:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5ef2b2948c7b7813479ba3adc7ff763` |
| SHA-1 | `810e2b507e8f9dd2ac93dc685b0562fec084daf7` |
| SHA-256 | `563512cbc00ac478207d204bf4fd686a533cfa7d8a3948c6d7ba94fb08716fa1` |
| SHA3-384 | `3bb3ecaf8b3dcbf8a8ca8f5cef49841a40fd47a5de5fb52108978c38f7d95cfaf2566141d0507601dab655bb43a8e6ec` |
| TLSH | `T112310F0ACBEF3BF9F41EC17A66160B7BA316F9440BB19245DF80E9586E481A42CD3135` |
| SSDEEP | `24:3Mu2Y3H3Al1944SlAnGJ+u9GcqiElFW0pJYjJZQtr52G9lcGK9U0p:z/004SlAnGwu9G9lFWC+Ytr52G96GKfp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_563512cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "563512cbc00ac478207d204bf4fd686a533cfa7d8a3948c6d7ba94fb08716fa1"
    family = "Mirai"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-08-21 21:42:38"
  condition:
    hash.sha256(0, filesize) == "563512cbc00ac478207d204bf4fd686a533cfa7d8a3948c6d7ba94fb08716fa1"
}
```

### Sample 80: `4189394952c2876e`

| Field | Value |
|---|---|
| SHA-256 | `4189394952c2876eab70eb7ce743fd3e7e7d72189045c10197059611f2a4da76` |
| Family label | `Mirai` |
| File name | `dlr.arm` |
| File type | `elf` |
| First seen | `2026-08-21 21:37:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f951e657a25d2cf95ecda3b7d5e31a2f` |
| SHA-1 | `3a945b774c77f3dd2d0e2db24ed6ecce8e2bf9d8` |
| SHA-256 | `4189394952c2876eab70eb7ce743fd3e7e7d72189045c10197059611f2a4da76` |
| SHA3-384 | `bf518faf1a416c8e13f1f93326f8da0a4800fdeda5c096ff97b7d16734457ce7664159430bcbc4b627b85e47163d4c99` |
| TLSH | `T16A21CE96A7E35D16CD840637DDAF5B20E322BF48C69EF503E31216251C7F31A1F21149` |
| TELFHASH | `t19f900224424f44549a804241e0dd66018ed0e3131125289007d0444014033206005141` |
| SSDEEP | `24:JKR4llMRgP9qD0at6EoDbGe88rUlFSy40VzLCkIddgvt+RGIUlZVNfW:JKqTFqDPty88rkFSy4CzLZHIUlZVNu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_41893949
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4189394952c2876eab70eb7ce743fd3e7e7d72189045c10197059611f2a4da76"
    family = "Mirai"
    file_name = "dlr.arm"
    file_type = "elf"
    first_seen = "2026-08-21 21:37:33"
  condition:
    hash.sha256(0, filesize) == "4189394952c2876eab70eb7ce743fd3e7e7d72189045c10197059611f2a4da76"
}
```

### Sample 81: `2622d2ab4694ba71`

| Field | Value |
|---|---|
| SHA-256 | `2622d2ab4694ba71c9c7970f664d623e94fa11af0159784c40a0538329538f53` |
| Family label | `Mirai` |
| File name | `dlr.x86_64` |
| File type | `elf` |
| First seen | `2026-08-21 21:35:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5a76e58085263066070e70f2419a941` |
| SHA-1 | `14ff57e054263ce1ae35cd9c1e8fac6b5d9756a7` |
| SHA-256 | `2622d2ab4694ba71c9c7970f664d623e94fa11af0159784c40a0538329538f53` |
| SHA3-384 | `2447fc8f0bdb33a18633d0b4c0e2f890f3406b58fa4082220263f2e2dc9bfdc58bb1a6a8dc8aaae25a8d59f96b936d99` |
| TLSH | `T1FA311203A79AD598D8A4DE7103E2503052F13D3F656EAF45670D5D363C87681E828011` |
| SSDEEP | `24:GYq9Gz0XezDXEN2EynR3Si1pgH/Bf2jb+s6BcjIX6OugsOBTTas:GJ9a0yXujMtBAf2jb+txXJZdV+s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_2622d2ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2622d2ab4694ba71c9c7970f664d623e94fa11af0159784c40a0538329538f53"
    family = "Mirai"
    file_name = "dlr.x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 21:35:42"
  condition:
    hash.sha256(0, filesize) == "2622d2ab4694ba71c9c7970f664d623e94fa11af0159784c40a0538329538f53"
}
```

### Sample 82: `2320a4529e5fddb6`

| Field | Value |
|---|---|
| SHA-256 | `2320a4529e5fddb64858e986cbb269062b8b0d1a0a360fa90e293c1e246166bf` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-21 21:30:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97dc2b1a6ed4e81c4cb9b6f65dfde90f` |
| SHA-1 | `325058bfc22a95c6f2baea835638f09b237304d2` |
| SHA-256 | `2320a4529e5fddb64858e986cbb269062b8b0d1a0a360fa90e293c1e246166bf` |
| SHA3-384 | `af32b5d45f89c26ce34e16b74d17ee6ae8a18cf88f8e0108bc977009c3256eebe554fccf20f34c80c7cdc3e01440b895` |
| TLSH | `T1D3046B17B5C194FDC8DAC1B44BEEE235EA72F0191134B61F17D4AF222E4DE20AB6DA50` |
| TELFHASH | `t18f61e1742d953c6821e3577ab34fe9e9fc3209610ee274e56e3ba8d1cf567c80d92012` |
| SSDEEP | `3072:/EfcKUmuCJPZNRAYGzDyYqy1l/eDkWmbZfaRGoL8eb+oYVJIy:eUXCWX5JRey9xesIy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_2320a452
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2320a4529e5fddb64858e986cbb269062b8b0d1a0a360fa90e293c1e246166bf"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 21:30:31"
  condition:
    hash.sha256(0, filesize) == "2320a4529e5fddb64858e986cbb269062b8b0d1a0a360fa90e293c1e246166bf"
}
```

### Sample 83: `4e5bbea0ace9f3b8`

| Field | Value |
|---|---|
| SHA-256 | `4e5bbea0ace9f3b808161896edcaf620c632385f74855174baff669af3dc9140` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-21 21:30:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a8de38230b172826b1f0358bbe57912` |
| SHA-1 | `bab510ca7e408bef7df4e061b5b3efcbc983d4d8` |
| SHA-256 | `4e5bbea0ace9f3b808161896edcaf620c632385f74855174baff669af3dc9140` |
| SHA3-384 | `3be8e88c63b77b14548f8c4d924461f889d4f3e70b62c5071673535f5c217f5c8ce179f66d0def1b74721f6e4c2df539` |
| TLSH | `T1D76301FFC3BDC9B0C3B1C03B2A2586C8FCA39C61527AAB4F64453CB72855D416A21D20` |
| SSDEEP | `1536:tEHc6nL4C8eRvDoruvpZwbYC1ql0k6+QZLfZhW9N3HQTG3n:cDnsCpRboruvpi0Cgl0k6rfZihHQTw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_4e5bbea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e5bbea0ace9f3b808161896edcaf620c632385f74855174baff669af3dc9140"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 21:30:02"
  condition:
    hash.sha256(0, filesize) == "4e5bbea0ace9f3b808161896edcaf620c632385f74855174baff669af3dc9140"
}
```

### Sample 84: `3944defd9ed83e16`

| Field | Value |
|---|---|
| SHA-256 | `3944defd9ed83e169d456ec5422aaaa5ba1882a632f02cc4b40e0d52406ccfd3` |
| Family label | `Mirai` |
| File name | `dlr.ppc` |
| File type | `elf` |
| First seen | `2026-08-21 21:28:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6aef0f607bdce3eb1a3afe7c6606e8dc` |
| SHA-1 | `12967249fafaf7ed42df97991eeed2cea4987647` |
| SHA-256 | `3944defd9ed83e169d456ec5422aaaa5ba1882a632f02cc4b40e0d52406ccfd3` |
| SHA3-384 | `81e5711ecc6aa0409dcedbcff4373e42fa2d7c0bca608db0083e78ac7dace98cf8a015094787e0fe26cad0d99b84db4b` |
| TLSH | `T124213577E75E1C52D0FBE1B945BA7765237066C68143F75573007C528A363B50D0DD0A` |
| SSDEEP | `24:30u0AXB/C/+LXavvz/k4lTcIYa7afFYnI4avhtj+W6S+S8ven:ku0AX4GLAz/llTcInI5vfj++p82n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_3944defd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3944defd9ed83e169d456ec5422aaaa5ba1882a632f02cc4b40e0d52406ccfd3"
    family = "Mirai"
    file_name = "dlr.ppc"
    file_type = "elf"
    first_seen = "2026-08-21 21:28:29"
  condition:
    hash.sha256(0, filesize) == "3944defd9ed83e169d456ec5422aaaa5ba1882a632f02cc4b40e0d52406ccfd3"
}
```

### Sample 85: `19dc8ef01a3671d4`

| Field | Value |
|---|---|
| SHA-256 | `19dc8ef01a3671d43868d90d36f625ab881359d2d49e7e4a8ee9bbeb9cd556f9` |
| Family label | `Mirai` |
| File name | `dlr.mpsl` |
| File type | `elf` |
| First seen | `2026-08-21 21:26:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7dbfba77c512422399232ac4caf5a4f` |
| SHA-1 | `14f506e44de6e7ee2c72be82c632e64f0295595f` |
| SHA-256 | `19dc8ef01a3671d43868d90d36f625ab881359d2d49e7e4a8ee9bbeb9cd556f9` |
| SHA3-384 | `d437697bccec1cf33be14980effdce3181d8430484baee1cc0a1bbdb507e273ac0cbebea6d06e448ec5b1e1a3d4b7bbe` |
| TLSH | `T1E631DB5ADDC5789EC44E9F70E69552AC0210834CAF622A2EEA6B0DC03CABE442B75424` |
| SSDEEP | `24:8nBxVmknwXcD7NH6EWJHD/wyoIBPXD9aE:2ZXwXcUEqBZXD9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_19dc8ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19dc8ef01a3671d43868d90d36f625ab881359d2d49e7e4a8ee9bbeb9cd556f9"
    family = "Mirai"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-08-21 21:26:35"
  condition:
    hash.sha256(0, filesize) == "19dc8ef01a3671d43868d90d36f625ab881359d2d49e7e4a8ee9bbeb9cd556f9"
}
```

### Sample 86: `75da2ad869488ae2`

| Field | Value |
|---|---|
| SHA-256 | `75da2ad869488ae22f7adae7dc72a33ca415e8f91578d00eda9d70222d1b02af` |
| Family label | `Mirai` |
| File name | `dlr.spc` |
| File type | `elf` |
| First seen | `2026-08-21 21:24:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c6444aeab68e1167c44d5bb73630a68` |
| SHA-1 | `9eb418360c26740b18f846e8766200d6a5f7cd32` |
| SHA-256 | `75da2ad869488ae22f7adae7dc72a33ca415e8f91578d00eda9d70222d1b02af` |
| SHA3-384 | `846a3a6cb57f6d0090b0b7c777f1db90ec2798cb7c5ad5f5a610996c87174f41543498ce7d231c3d33eaed42de5acd78` |
| TLSH | `T1F721EE36D77C053AFE6CA0FF083743229763A0089F36234459C52F60AC15394FE1515E` |
| SSDEEP | `24:3hcVYxrZsYyM/A3Ftoz5fduG6cGEhV1zgDjAkwFSP4ArItlZPzO8vB1Gb:OJYyNcd+cGouckw7A8tlZPzO8Cb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_75da2ad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75da2ad869488ae22f7adae7dc72a33ca415e8f91578d00eda9d70222d1b02af"
    family = "Mirai"
    file_name = "dlr.spc"
    file_type = "elf"
    first_seen = "2026-08-21 21:24:33"
  condition:
    hash.sha256(0, filesize) == "75da2ad869488ae22f7adae7dc72a33ca415e8f91578d00eda9d70222d1b02af"
}
```

### Sample 87: `2410b4ca59e2f8b6`

| Field | Value |
|---|---|
| SHA-256 | `2410b4ca59e2f8b6272118e0478357c8ac6889678f26ae85c2a07f6c451d6652` |
| Family label | `Mirai` |
| File name | `dlr.m68k` |
| File type | `elf` |
| First seen | `2026-08-21 21:24:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76a85b3286f4ba692cb82fbb32208ec8` |
| SHA-1 | `547e088b697b3f70581688c2486fc97d3d69a653` |
| SHA-256 | `2410b4ca59e2f8b6272118e0478357c8ac6889678f26ae85c2a07f6c451d6652` |
| SHA3-384 | `d082c7ec6949402c544653124c47f96ede19f565d3ee8261c219d9b13893bb4aae3214669a24856e8867bdedbd05cab6` |
| TLSH | `T1E011884BAB85AE20ED4570BE4F8307092DD1AD2A9B26DA07335040173E6A7F06D1CABC` |
| SSDEEP | `12:BBAXs5w/Ptahx5TnaY/3nZAEukih3F7CeWiuiMY4XN/rbLme4ya0lE9iL+M2BQtt:3VetMxNa8ZAEu/T3pqXd/n4p1ALBztt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_2410b4ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2410b4ca59e2f8b6272118e0478357c8ac6889678f26ae85c2a07f6c451d6652"
    family = "Mirai"
    file_name = "dlr.m68k"
    file_type = "elf"
    first_seen = "2026-08-21 21:24:32"
  condition:
    hash.sha256(0, filesize) == "2410b4ca59e2f8b6272118e0478357c8ac6889678f26ae85c2a07f6c451d6652"
}
```

### Sample 88: `3d24252d5fba5a20`

| Field | Value |
|---|---|
| SHA-256 | `3d24252d5fba5a20879ed518a37994f2268bc463d9cfb2995f6e6521eb94e965` |
| Family label | `Mirai` |
| File name | `e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af.elf` |
| File type | `elf` |
| First seen | `2026-08-21 21:22:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcf9ba5aa3c24ca99da427aa2be35bc6` |
| SHA-1 | `d9d9e1790f74244f2661a542d393e27dd480120a` |
| SHA-256 | `3d24252d5fba5a20879ed518a37994f2268bc463d9cfb2995f6e6521eb94e965` |
| SHA3-384 | `ec747b96554d6edaeb851b42c5434381aee897ea52e73042fe0fd59337e34fd5ea32d8619b79d05b12a05ec1c0a83eb8` |
| TLSH | `T1F604F755FC418B16CAC366BBFF4E428D77270768D3EE72039D156F21278A86A0E3B146` |
| TELFHASH | `t1db316450cfdc29acbbe50898d1eda21b61e434f8a9282831adaddf9e0e134d17034c36` |
| SSDEEP | `3072:JKR8t9N2qpMFoCqgtDs51G16Jw81KUUBqSSO83l5wCkmnDpPHsw3bgiTjDk4HnKB:JKR89NtpCoCqgq51KcwGS3t83l5wDmna` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_3d24252d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d24252d5fba5a20879ed518a37994f2268bc463d9cfb2995f6e6521eb94e965"
    family = "Mirai"
    file_name = "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af.elf"
    file_type = "elf"
    first_seen = "2026-08-21 21:22:19"
  condition:
    hash.sha256(0, filesize) == "3d24252d5fba5a20879ed518a37994f2268bc463d9cfb2995f6e6521eb94e965"
}
```

### Sample 89: `e405bcbf4e1b8a8b`

| Field | Value |
|---|---|
| SHA-256 | `e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af` |
| Family label | `Mirai` |
| File name | `e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af.elf` |
| File type | `elf` |
| First seen | `2026-08-21 21:21:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac62f39c101304d31ecb789d08870189` |
| SHA-1 | `f9744c3bb85f886e498be1bc4d10f9b06d91b040` |
| SHA-256 | `e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af` |
| SHA3-384 | `346b509214e37b7da9fcd593f975bedcb103b07f6d9e1f4d0dc0b461f8ff03e60e608de380cbfbab31a4d60a191094b0` |
| TLSH | `T1B66302C0AD2404C9E3F2603FBC2D9548D7E3467098E5BC1B2AEE5E6C53B62477ABD161` |
| SSDEEP | `1536:G8c1HrRncmY+vZeXvezZMWqQujRuyhE4zWf:GDcX+YXGZZGkyX0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_e405bcbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af"
    family = "Mirai"
    file_name = "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af.elf"
    file_type = "elf"
    first_seen = "2026-08-21 21:21:11"
  condition:
    hash.sha256(0, filesize) == "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af"
}
```

### Sample 90: `e448e02e582c8a47`

| Field | Value |
|---|---|
| SHA-256 | `e448e02e582c8a4746204b93ebeb0545515b2aede8e5bd789fd7ec6ce06c0c03` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-08-21 21:17:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca62b338ad925fd2d9d59a7e962143f3` |
| SHA-1 | `230e14135aa243359a5737d7e38a0fedf63bfd62` |
| SHA-256 | `e448e02e582c8a4746204b93ebeb0545515b2aede8e5bd789fd7ec6ce06c0c03` |
| SHA3-384 | `1fda531663f59a2c00b3541002772a1f21ed35d00d95a2bbf8d0456921a8c2fb359e47742094c3a1d11ca87a8b9d15f7` |
| TLSH | `T1EE044B01B71D0943E2632EF03A3B27D1C3EF9A9125F9EB44690FAA899171D321586DDF` |
| SSDEEP | `3072:j6XyRGseFV46NEWPxxCHAEVhQt87DTOT0T4Hts:jyyRGB4iPxMHHhQt8nTOOis` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_e448e02e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e448e02e582c8a4746204b93ebeb0545515b2aede8e5bd789fd7ec6ce06c0c03"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-21 21:17:17"
  condition:
    hash.sha256(0, filesize) == "e448e02e582c8a4746204b93ebeb0545515b2aede8e5bd789fd7ec6ce06c0c03"
}
```

### Sample 91: `0cca6c20b4466d2d`

| Field | Value |
|---|---|
| SHA-256 | `0cca6c20b4466d2db1fb8427ca21c85cdd7c1c460554112f0a238a3d594b2a0e` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-08-21 21:16:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31427f8fffaf45746c02c263c5e45236` |
| SHA-1 | `37704ae64f749c90d11757fc4ea6da81be7c832c` |
| SHA-256 | `0cca6c20b4466d2db1fb8427ca21c85cdd7c1c460554112f0a238a3d594b2a0e` |
| SHA3-384 | `26efbe056a032603beadf447ee6d11f5605c1f6b32333e18688c65320d3b149569b58d550cfa8bac5578282be72df71e` |
| TLSH | `T1C16302D08B61514CFAEFF943AC98EFC257162FCA76304DF16E1A5B0A6A605243052FDA` |
| SSDEEP | `1536:ydZdca6QoSrGLOhs7MIdvCpGKeKHAq4G4u+qgw097:yFcUrXhsQu4GMHf4G4u+qgwK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_0cca6c20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cca6c20b4466d2db1fb8427ca21c85cdd7c1c460554112f0a238a3d594b2a0e"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-21 21:16:39"
  condition:
    hash.sha256(0, filesize) == "0cca6c20b4466d2db1fb8427ca21c85cdd7c1c460554112f0a238a3d594b2a0e"
}
```

### Sample 92: `16ba5736f615fbb3`

| Field | Value |
|---|---|
| SHA-256 | `16ba5736f615fbb3c7a9861c6de1dac8b9eb6757ae815786306ed4f6c6b7bc4f` |
| Family label | `RemusStealer` |
| File name | `1e15f05977d0d5ddde505be77dd3b2ef.exe` |
| File type | `exe` |
| First seen | `2026-08-21 21:15:14` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e15f05977d0d5ddde505be77dd3b2ef` |
| SHA-1 | `68b4734af511bb33cdb2b5c7d4b367956feeb0da` |
| SHA-256 | `16ba5736f615fbb3c7a9861c6de1dac8b9eb6757ae815786306ed4f6c6b7bc4f` |
| SHA3-384 | `f8e938a83d6fa86fd574e6a560945647ecce77d8796500b29c8476747e13bed8133fd7ed6219ab44577df10a5836895c` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1D2B57B07BC9444B9C4AA933A89B60656B675FC148F3A33DB3E50FA782F317D15A38B50` |
| SSDEEP | `24576:jP8Sxx0kpTZ5HGPkwokq7U2OaMBC4Hn24/NT2TCnJ8GFPeI2p:QQx0oLHaokSOaMBC4W4/ZdGrp` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_092_16ba5736
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16ba5736f615fbb3c7a9861c6de1dac8b9eb6757ae815786306ed4f6c6b7bc4f"
    family = "RemusStealer"
    file_name = "1e15f05977d0d5ddde505be77dd3b2ef.exe"
    file_type = "exe"
    first_seen = "2026-08-21 21:15:14"
  condition:
    hash.sha256(0, filesize) == "16ba5736f615fbb3c7a9861c6de1dac8b9eb6757ae815786306ed4f6c6b7bc4f"
}
```

### Sample 93: `0a3f4115a9495dca`

| Field | Value |
|---|---|
| SHA-256 | `0a3f4115a9495dca557abff7445aec5d7773906fd91a0b2060f32c2cb42ad8b7` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 21:12:23` |
| Reporter | `Bitsight` |
| Tags | `a47659cdad283e9dcd10da78ff795967, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee2317eedfe58fb78a2541c2277b8f6a` |
| SHA-1 | `ea22226bb24f1e6da19ed17f7beccf0b2a1d3380` |
| SHA-256 | `0a3f4115a9495dca557abff7445aec5d7773906fd91a0b2060f32c2cb42ad8b7` |
| SHA3-384 | `218f8a4415e3f08e069d2bbba2a50b3d32d02fb96cb441ff1d6797c77b2310a2de8e180dd2c8073d3a3a32cdfc0153d3` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T19C36338AB58AE574D403C7F8496331AE737E7BE18A61BD2E37CE1B100E4AE14543E791` |
| SSDEEP | `98304:mo2saElT0+GSY1VOaY+sLgJYpV7gfHFUJF0FYiCwVd:m0aElI+Gv1VOX+skJIwVFYiCwH` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_093_0a3f4115
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a3f4115a9495dca557abff7445aec5d7773906fd91a0b2060f32c2cb42ad8b7"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:12:23"
  condition:
    hash.sha256(0, filesize) == "0a3f4115a9495dca557abff7445aec5d7773906fd91a0b2060f32c2cb42ad8b7"
}
```

### Sample 94: `b28bdb3846a844a2`

| Field | Value |
|---|---|
| SHA-256 | `b28bdb3846a844a25300d1f595da9339cc8e5f830312d55bc15ffed6e2c0bd88` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 21:12:16` |
| Reporter | `Bitsight` |
| Tags | `a47659cdad283e9dcd10da78ff795967, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad77e6adaadc8fc5898ad4118a4cd1d2` |
| SHA-1 | `7dc0e8ea0b99f9b8cfe3c83aed9d6e167fb84a80` |
| SHA-256 | `b28bdb3846a844a25300d1f595da9339cc8e5f830312d55bc15ffed6e2c0bd88` |
| SHA3-384 | `05c2817635143f0537d9f3675ab5e2dc440732e4e98ab7ca508f5a6d77421ac8637d225982c91cc9780501f6aea5b5f8` |
| IMPHASH | `cc678ea372003a91fefb68ce6b422039` |
| TLSH | `T12FD523CAB1F63D70D473C772AF92E07DB0AEBB5009908D4AFACD79009E62944497B275` |
| SSDEEP | `49152:HtXWVkZazDmc9bdb7vJOC4g5JAGsbs90857JixwwmFhBMmtc45OKb:H9W20R9p/JO1g5JhO8DixNmDBMm6YT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_b28bdb38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b28bdb3846a844a25300d1f595da9339cc8e5f830312d55bc15ffed6e2c0bd88"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:12:16"
  condition:
    hash.sha256(0, filesize) == "b28bdb3846a844a25300d1f595da9339cc8e5f830312d55bc15ffed6e2c0bd88"
}
```

### Sample 95: `d5ace966356f1533`

| Field | Value |
|---|---|
| SHA-256 | `d5ace966356f153320ee9442332fbf3e35e89fe8b217c4a27707d9406b7e14a4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 21:12:06` |
| Reporter | `Bitsight` |
| Tags | `a47659cdad283e9dcd10da78ff795967, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f532e57d8a0916398981917eeb40496` |
| SHA-1 | `2ae66d65d7d5026951a878700ec14bdb6991c3b2` |
| SHA-256 | `d5ace966356f153320ee9442332fbf3e35e89fe8b217c4a27707d9406b7e14a4` |
| SHA3-384 | `56cf916488f93efa0340f9b8836c2e301189136bd19191113f4b647e7facbfa828f36aaf5e9061692eb2bab4271110b0` |
| IMPHASH | `24e8765fd838d429e6f908cdeb96c2d6` |
| TLSH | `T126D5238AFDF25470E833C7768293607DB12977958B785C9736CCAB006E52615AC33B3A` |
| SSDEEP | `49152:0NDTnFv4TpwXYW7DPcCcdUG9wTxBqa/EQBr0qW4pUZ2QPzum9NbR3VOOACxALK:0NDrFkaXY2xYUG92zWuUZ2QrFNtVOOJ+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_d5ace966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5ace966356f153320ee9442332fbf3e35e89fe8b217c4a27707d9406b7e14a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:12:06"
  condition:
    hash.sha256(0, filesize) == "d5ace966356f153320ee9442332fbf3e35e89fe8b217c4a27707d9406b7e14a4"
}
```

### Sample 96: `82f64f6ba04dd9ee`

| Field | Value |
|---|---|
| SHA-256 | `82f64f6ba04dd9ee1d96ad0198db8b6b55a83b301a9f099692280b7996850e76` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-08-21 21:09:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71ac626a390d813489ce2e396fe4a19d` |
| SHA-1 | `9a9dc296c1769f7a68375166b47c5fcd86d30ffa` |
| SHA-256 | `82f64f6ba04dd9ee1d96ad0198db8b6b55a83b301a9f099692280b7996850e76` |
| SHA3-384 | `f1cb767ee999dd278c35c2d51ec6e6a0a525db4f6f98783ba760f34e4dbc9f1550ef34cad90e097b3e79af3bcfb5974f` |
| TLSH | `T1AC040856F8819B12D5C255BAFE0E128E33131B78E3DE72129D246F75678A8BF0E3B405` |
| TELFHASH | `t106110000df0c09d8a3f64245d5fafd0563ad319922061c79a8bc5d9e8a2b9cbb03880e` |
| SSDEEP | `3072:vplEQWNaeA8748NxAPKIV/NrQR0EjtttlMMd0abJ1EszupVvPnDPIBWZo0P4H5:vplEQ8PZ748NOhV5i0MtaMGat1bIVvPS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_82f64f6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82f64f6ba04dd9ee1d96ad0198db8b6b55a83b301a9f099692280b7996850e76"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-21 21:09:20"
  condition:
    hash.sha256(0, filesize) == "82f64f6ba04dd9ee1d96ad0198db8b6b55a83b301a9f099692280b7996850e76"
}
```

### Sample 97: `ae0adf8657f3b3f1`

| Field | Value |
|---|---|
| SHA-256 | `ae0adf8657f3b3f1f54a0d2f83f4eca7281c96cb61eb5d053cf239b1a7ded26a` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-08-21 21:08:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c5ae3c1ef4bb177292a1791b40a4990` |
| SHA-1 | `89ab884b612c90d54db9c71bbd834e1f1f6a8d90` |
| SHA-256 | `ae0adf8657f3b3f1f54a0d2f83f4eca7281c96cb61eb5d053cf239b1a7ded26a` |
| SHA3-384 | `d3f3edca6eca7b3badc4a1ab387a54fc7dfdaa5f59f9199b2a9e6ee56ea9a6877c5a726ba4e2ceae6ba21e8f66dd452d` |
| TLSH | `T12173020146626122CC04F97DD77AC9E6FFE54FF8C01974A88789B2ACF9819C76F246E1` |
| SSDEEP | `1536:UvgkXoalvUrcuUebSrEeFjAg+HExBXHZ0KTZ/IngLI:UvgKRJupNujAZwL0KF6gLI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_ae0adf86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0adf8657f3b3f1f54a0d2f83f4eca7281c96cb61eb5d053cf239b1a7ded26a"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-21 21:08:30"
  condition:
    hash.sha256(0, filesize) == "ae0adf8657f3b3f1f54a0d2f83f4eca7281c96cb61eb5d053cf239b1a7ded26a"
}
```

### Sample 98: `81eb84e7cebbfc48`

| Field | Value |
|---|---|
| SHA-256 | `81eb84e7cebbfc48853bf4dda7525fb3b21b5014a845d13784f441cda8264906` |
| Family label | `unknown` |
| File name | `goodthingsforbestpersonforme.hta` |
| File type | `hta` |
| First seen | `2026-08-21 21:04:42` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c1aa1d882561d64cb422a0930b901e4` |
| SHA-1 | `3e9a65fc3bb0bc475635e9120a64dc8c244ec6d5` |
| SHA-256 | `81eb84e7cebbfc48853bf4dda7525fb3b21b5014a845d13784f441cda8264906` |
| SHA3-384 | `bc69bc00ea2c7630f241634ad882dc77ee5504780b00f7a83abb3c2c672930ba1c046a44ef2ff404c7147540944ab355` |
| TLSH | `T184F05C4594A04D19523016147EC1FA055E96EB478389AD4C72AA51B91FC47C2CDCF8BC` |
| SSDEEP | `6:qTIuJzhqIwGiY63fAbplilAl3t11/+SR0AqIbR2AWHwlVmsV4LKTjawlp7dF0NAg:qTp0JYyg9193R5qsPWqmsVJdqAEd2QL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_81eb84e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81eb84e7cebbfc48853bf4dda7525fb3b21b5014a845d13784f441cda8264906"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-08-21 21:04:42"
  condition:
    hash.sha256(0, filesize) == "81eb84e7cebbfc48853bf4dda7525fb3b21b5014a845d13784f441cda8264906"
}
```

### Sample 99: `d5309edae0b8fcb0`

| Field | Value |
|---|---|
| SHA-256 | `d5309edae0b8fcb08ddaa46704ff1199ded4b235c5ae40ef53fd6767f124c008` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-21 21:02:21` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81e74dd89b3afd01a067949ca5fd4fe6` |
| SHA-1 | `551b5638b82ec973951636e13e1fc3d8c5d8cb3c` |
| SHA-256 | `d5309edae0b8fcb08ddaa46704ff1199ded4b235c5ae40ef53fd6767f124c008` |
| SHA3-384 | `f00e4aadb156697629ff694b65f7ddac990fed4b5ef6ecc9ea7facab0906d7ded5925c080aed08d68bdbd0d5c6e05c93` |
| IMPHASH | `cc7360b7af0e7d6c74ce4bcd10f5bece` |
| TLSH | `T1E485DB785E27F8E07E9D38249A25A335893418F8D474AC763EF47442E39ECA5B5CD322` |
| SSDEEP | `768:GyGIki31FkR29Svbtn2KxiUcoHVBphM6jhuouYk4bq1kWDZ6DsrPz4/v1:G5Yc24w4CmVXhMmTLbNC6v1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_d5309eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5309edae0b8fcb08ddaa46704ff1199ded4b235c5ae40ef53fd6767f124c008"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:02:21"
  condition:
    hash.sha256(0, filesize) == "d5309edae0b8fcb08ddaa46704ff1199ded4b235c5ae40ef53fd6767f124c008"
}
```

### Sample 100: `f5c0fabbc05edbd7`

| Field | Value |
|---|---|
| SHA-256 | `f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092` |
| Family label | `unknown` |
| File name | `f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092` |
| File type | `elf` |
| First seen | `2026-08-21 21:00:21` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d215e62bc386000c3e845ea479a49e25` |
| SHA-1 | `d6099c35f4271135cd91b0c8b4762ff80e9938b1` |
| SHA-256 | `f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092` |
| SHA3-384 | `e694e0599c6731fc26db51f8a81033067aa82b4a982b7b4fa99a113c64bd7cb3df606b6fd226f43ba768c6ff9cd36e2f` |
| TLSH | `T1E7F69D77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQA:cqYUQuVDt0TZEb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_f5c0fabb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092"
    family = "unknown"
    file_name = "f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092"
    file_type = "elf"
    first_seen = "2026-08-21 21:00:21"
  condition:
    hash.sha256(0, filesize) == "f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092"
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
 * Generated: 2026-08-22T01:53:19.747381+00:00
 */

rule MalwareBazaar_unknown_001_bb1a0a0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb1a0a0ca087de0e231f567453d5652fa2af5819412ee602e0ffd601f1a186ec"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 01:52:11"
  condition:
    hash.sha256(0, filesize) == "bb1a0a0ca087de0e231f567453d5652fa2af5819412ee602e0ffd601f1a186ec"
}

rule MalwareBazaar_Mirai_002_8c848798
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f"
    family = "Mirai"
    file_name = "8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 01:51:03"
  condition:
    hash.sha256(0, filesize) == "8c848798aab18991fdc4df17950daa818c78fbd2a51d75c779f8a3440638592f"
}

rule MalwareBazaar_unknown_003_49b81f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49b81f37896cb76b7a2b54a1bdac64caeb1513abf26ddc8da5f9e24f9ab74390"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:49:44"
  condition:
    hash.sha256(0, filesize) == "49b81f37896cb76b7a2b54a1bdac64caeb1513abf26ddc8da5f9e24f9ab74390"
}

rule MalwareBazaar_unknown_004_303555a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "303555a2115d8510f7f8e663e3c25a3310000c3a20950089633902c6245f7cc3"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:48:53"
  condition:
    hash.sha256(0, filesize) == "303555a2115d8510f7f8e663e3c25a3310000c3a20950089633902c6245f7cc3"
}

rule MalwareBazaar_unknown_005_6d70fb7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d70fb7ee01bcca86fde4aa7154ae198eeacf9dbc852c824fe2317397ce1f1de"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:47:51"
  condition:
    hash.sha256(0, filesize) == "6d70fb7ee01bcca86fde4aa7154ae198eeacf9dbc852c824fe2317397ce1f1de"
}

rule MalwareBazaar_unknown_006_799a7ba7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "799a7ba7f0e68529c61e4cb73bd8a1e57d5648786937335e36e53ed1ab56a932"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:46:56"
  condition:
    hash.sha256(0, filesize) == "799a7ba7f0e68529c61e4cb73bd8a1e57d5648786937335e36e53ed1ab56a932"
}

rule MalwareBazaar_unknown_007_57713a4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57713a4f584665cbb42ecddd749459c10c7a369e3b1beaaabd4d694891e16933"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:46:02"
  condition:
    hash.sha256(0, filesize) == "57713a4f584665cbb42ecddd749459c10c7a369e3b1beaaabd4d694891e16933"
}

rule MalwareBazaar_ValleyRAT_008_2779033e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2779033e8c0bd3d1c2332d1a4c498b09d2eb090fff10a5aad7adbfb3a5231d72"
    family = "ValleyRAT"
    file_name = "FCFA826B899EE297DF49F4EF756857D2.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:45:24"
  condition:
    hash.sha256(0, filesize) == "2779033e8c0bd3d1c2332d1a4c498b09d2eb090fff10a5aad7adbfb3a5231d72"
}

rule MalwareBazaar_unknown_009_2b435e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b435e783dd02a969e3ebbef2e88898faa654e72fe48bca19d8328eed051b6ed"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:45:02"
  condition:
    hash.sha256(0, filesize) == "2b435e783dd02a969e3ebbef2e88898faa654e72fe48bca19d8328eed051b6ed"
}

rule MalwareBazaar_unknown_010_b3e188bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3e188bf57cbc7a25832ea1623180c43508e31c9dfcd50c914b42954d6dd8ca9"
    family = "unknown"
    file_name = "ae_mixtwo.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:44:02"
  condition:
    hash.sha256(0, filesize) == "b3e188bf57cbc7a25832ea1623180c43508e31c9dfcd50c914b42954d6dd8ca9"
}

rule MalwareBazaar_RemusStealer_011_8dcda89a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dcda89abe8d1192c60f5e2ce46af13ff4a73411eb2ad1311ff80fd54541c20b"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:42:58"
  condition:
    hash.sha256(0, filesize) == "8dcda89abe8d1192c60f5e2ce46af13ff4a73411eb2ad1311ff80fd54541c20b"
}

rule MalwareBazaar_Mirai_012_fd207faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f"
    family = "Mirai"
    file_name = "fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 01:36:09"
  condition:
    hash.sha256(0, filesize) == "fd207faa41eb1537790fcc4036c3250c93c5563ec275b36b191c74a90e0a703f"
}

rule MalwareBazaar_ValleyRAT_013_749d02aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749d02aacf954ce95077efc5084679a11ee474799b9961c069413f60278ab854"
    family = "ValleyRAT"
    file_name = "F7120F15B4B3E4622E8EAF5E8F664D0C.dll"
    file_type = "dll"
    first_seen = "2026-08-22 01:35:19"
  condition:
    hash.sha256(0, filesize) == "749d02aacf954ce95077efc5084679a11ee474799b9961c069413f60278ab854"
}

rule MalwareBazaar_unknown_014_fd01de88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175"
    family = "unknown"
    file_name = "fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175"
    file_type = "sh"
    first_seen = "2026-08-22 01:30:25"
  condition:
    hash.sha256(0, filesize) == "fd01de8844ac6f7c2bd35b66f974a79ddcd6ca21a247157a270419d32c266175"
}

rule MalwareBazaar_unknown_015_68646c5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70"
    family = "unknown"
    file_name = "68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70"
    file_type = "sh"
    first_seen = "2026-08-22 01:30:19"
  condition:
    hash.sha256(0, filesize) == "68646c5e06443730a2dc90e97c35c6038b65b0e70d91a61e91ceddf6eceffa70"
}

rule MalwareBazaar_Mirai_016_a2eb9cf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2eb9cf201f057f9860abfbd377b58d390165b6c86ff9a23f848ee0142b40f7b"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-22 01:15:58"
  condition:
    hash.sha256(0, filesize) == "a2eb9cf201f057f9860abfbd377b58d390165b6c86ff9a23f848ee0142b40f7b"
}

rule MalwareBazaar_ValleyRAT_017_60507a4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60507a4f30c4b1f8667be1b809caa854f65661b3741054fa73e133d3944a402e"
    family = "ValleyRAT"
    file_name = "DDAA70755BF4E96F0A21663D55D978A0.dll"
    file_type = "dll"
    first_seen = "2026-08-22 01:15:19"
  condition:
    hash.sha256(0, filesize) == "60507a4f30c4b1f8667be1b809caa854f65661b3741054fa73e133d3944a402e"
}

rule MalwareBazaar_RemusStealer_018_5239ca97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5239ca97f24a7b84ec35362adcca03935e29bc9082e3aa69c5ac73c7ac2efb19"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:13:23"
  condition:
    hash.sha256(0, filesize) == "5239ca97f24a7b84ec35362adcca03935e29bc9082e3aa69c5ac73c7ac2efb19"
}

rule MalwareBazaar_RemusStealer_019_9f4e2dc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f4e2dc6f2aeeb950936285e8e47f805d4e3d843e0912df08f49dc6e53bdf152"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:12:10"
  condition:
    hash.sha256(0, filesize) == "9f4e2dc6f2aeeb950936285e8e47f805d4e3d843e0912df08f49dc6e53bdf152"
}

rule MalwareBazaar_RemusStealer_020_c2dd3509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2dd3509770770764b86e5ac7dacd4805ceed98708b27a208a4973e3d4f7c3ea"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:11:08"
  condition:
    hash.sha256(0, filesize) == "c2dd3509770770764b86e5ac7dacd4805ceed98708b27a208a4973e3d4f7c3ea"
}

rule MalwareBazaar_RemusStealer_021_74a9d856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74a9d856028ed2daf9b4ac1db1f6da9ca8140599d0e3cf223687d15ee66f3c0f"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:10:01"
  condition:
    hash.sha256(0, filesize) == "74a9d856028ed2daf9b4ac1db1f6da9ca8140599d0e3cf223687d15ee66f3c0f"
}

rule MalwareBazaar_RemusStealer_022_a4da7669
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4da7669180c6c0cbd4c20bcf12906bccec11233e950a90942d20d3984fe2d94"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:08:46"
  condition:
    hash.sha256(0, filesize) == "a4da7669180c6c0cbd4c20bcf12906bccec11233e950a90942d20d3984fe2d94"
}

rule MalwareBazaar_RemusStealer_023_42c2c180
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42c2c18036a33df2229285065cdcbd7d6fbfd1cdbb9b121fc0160f98c075add7"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:07:38"
  condition:
    hash.sha256(0, filesize) == "42c2c18036a33df2229285065cdcbd7d6fbfd1cdbb9b121fc0160f98c075add7"
}

rule MalwareBazaar_RemusStealer_024_e1ceb7fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1ceb7fc212e182239ef470559bc0ee09c8fb12fa69f6ae09dee072bfecfb2b9"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:05:26"
  condition:
    hash.sha256(0, filesize) == "e1ceb7fc212e182239ef470559bc0ee09c8fb12fa69f6ae09dee072bfecfb2b9"
}

rule MalwareBazaar_ValleyRAT_025_e63dc60b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e63dc60b24b94658992abec4e5819be35bc0ed5bfc3fe65a89f320539236a181"
    family = "ValleyRAT"
    file_name = "CFDD3706B8A218872E16A5F496617398.dll"
    file_type = "dll"
    first_seen = "2026-08-22 01:05:10"
  condition:
    hash.sha256(0, filesize) == "e63dc60b24b94658992abec4e5819be35bc0ed5bfc3fe65a89f320539236a181"
}

rule MalwareBazaar_RemusStealer_026_47630a06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47630a069e44a6981ac37e9d82ae44e7252ed184ccb30f41f2df56f26254bd40"
    family = "RemusStealer"
    file_name = "ae_mixtwo.exe"
    file_type = "exe"
    first_seen = "2026-08-22 01:03:55"
  condition:
    hash.sha256(0, filesize) == "47630a069e44a6981ac37e9d82ae44e7252ed184ccb30f41f2df56f26254bd40"
}

rule MalwareBazaar_Mirai_027_4da675a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c"
    family = "Mirai"
    file_name = "4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c.elf"
    file_type = "elf"
    first_seen = "2026-08-22 01:01:06"
  condition:
    hash.sha256(0, filesize) == "4da675a2133e1b05fafb6a8186d165818855629373425ad93d6e5151fd95e47c"
}

rule MalwareBazaar_RemusStealer_028_3db21013
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3db21013142719a5845a82e09d29e975f80caffa5649b5e4e7e6f3c229d0feb4"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:53:52"
  condition:
    hash.sha256(0, filesize) == "3db21013142719a5845a82e09d29e975f80caffa5649b5e4e7e6f3c229d0feb4"
}

rule MalwareBazaar_RemusStealer_029_3ef0276b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ef0276b36b843e6e1e39065d9c413d45515f09cd115f3c0e1dc25b227fc3e9d"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:53:06"
  condition:
    hash.sha256(0, filesize) == "3ef0276b36b843e6e1e39065d9c413d45515f09cd115f3c0e1dc25b227fc3e9d"
}

rule MalwareBazaar_NeedleStealer_030_31611a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31611a93846b3d2307c7640e5bf04416ce3b0d337db0db5f69cdb408ca3be5d6"
    family = "NeedleStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:51:59"
  condition:
    hash.sha256(0, filesize) == "31611a93846b3d2307c7640e5bf04416ce3b0d337db0db5f69cdb408ca3be5d6"
}

rule MalwareBazaar_RemusStealer_031_b95ac535
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95ac535ed7651f441589fb37db059d76bc2384c417e910fc264aa006d115c49"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:51:10"
  condition:
    hash.sha256(0, filesize) == "b95ac535ed7651f441589fb37db059d76bc2384c417e910fc264aa006d115c49"
}

rule MalwareBazaar_RemusStealer_032_ae920045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae9200450fb3030b59e0a5a27eb2ab413297f0a0bdb4cb8a6755e64f38a07ff5"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:50:30"
  condition:
    hash.sha256(0, filesize) == "ae9200450fb3030b59e0a5a27eb2ab413297f0a0bdb4cb8a6755e64f38a07ff5"
}

rule MalwareBazaar_RemusStealer_033_8e2f9c7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e2f9c7c115d3137f5c993b0178395bca50aad733abc1ad336678b274662d4b6"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:49:14"
  condition:
    hash.sha256(0, filesize) == "8e2f9c7c115d3137f5c993b0178395bca50aad733abc1ad336678b274662d4b6"
}

rule MalwareBazaar_RemusStealer_034_3295712c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3295712cfe22112ee05a194478533ae0beb4ab46b0f5b38c75c09beb865b8bd7"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:48:18"
  condition:
    hash.sha256(0, filesize) == "3295712cfe22112ee05a194478533ae0beb4ab46b0f5b38c75c09beb865b8bd7"
}

rule MalwareBazaar_unknown_035_58645316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883"
    family = "unknown"
    file_name = "586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:46:14"
  condition:
    hash.sha256(0, filesize) == "586453165bf6649d38354376e4bfe78977f9f2a4cc0ab4eb87cc58fa552c2883"
}

rule MalwareBazaar_Mirai_036_8a613f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000"
    family = "Mirai"
    file_name = "8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000.elf"
    file_type = "elf"
    first_seen = "2026-08-22 00:46:07"
  condition:
    hash.sha256(0, filesize) == "8a613f3578531c2cb944b4fb3668f39288d22fb1b2af59ce0f22327ef72cc000"
}

rule MalwareBazaar_ValleyRAT_037_11974ece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11974ece6c707759b83574eaf844a6fbeebb55c16ac2b5b81d89d7200905733e"
    family = "ValleyRAT"
    file_name = "ABFCAB533D0BB4F3D44677FE84CE87BF.dll"
    file_type = "dll"
    first_seen = "2026-08-22 00:40:11"
  condition:
    hash.sha256(0, filesize) == "11974ece6c707759b83574eaf844a6fbeebb55c16ac2b5b81d89d7200905733e"
}

rule MalwareBazaar_Socks5Systemz_038_4b9d68a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b9d68a24e5bf83ee32a8feb43a9b74b4955c35dce3564ae62a137b7101eb903"
    family = "Socks5Systemz"
    file_name = "DCompAPI.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:38:26"
  condition:
    hash.sha256(0, filesize) == "4b9d68a24e5bf83ee32a8feb43a9b74b4955c35dce3564ae62a137b7101eb903"
}

rule MalwareBazaar_RemusStealer_039_78a2d298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a2d2988751b159ab860349e3dd1a9f034f4f1ef4d39888b66a4c924b7e9db0"
    family = "RemusStealer"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:37:16"
  condition:
    hash.sha256(0, filesize) == "78a2d2988751b159ab860349e3dd1a9f034f4f1ef4d39888b66a4c924b7e9db0"
}

rule MalwareBazaar_RemusStealer_040_73e065dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73e065dc63b3c7a08f3f940ed7cbf761129767b191f78a9621f5b4d305cedc71"
    family = "RemusStealer"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:36:36"
  condition:
    hash.sha256(0, filesize) == "73e065dc63b3c7a08f3f940ed7cbf761129767b191f78a9621f5b4d305cedc71"
}

rule MalwareBazaar_RemusStealer_041_6a406376
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a406376be3f0dc3c700a8c637b5c4a111c8e013b49f2100dace21520aeec4b8"
    family = "RemusStealer"
    file_name = "526993537.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:35:41"
  condition:
    hash.sha256(0, filesize) == "6a406376be3f0dc3c700a8c637b5c4a111c8e013b49f2100dace21520aeec4b8"
}

rule MalwareBazaar_unknown_042_b8557a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8557a6e283fc71cf39f68d2219a17599c2a6bd62d6c038aaacf10dc003d2408"
    family = "unknown"
    file_name = "DCompAPI.exe"
    file_type = "unknown"
    first_seen = "2026-08-22 00:31:13"
  condition:
    hash.sha256(0, filesize) == "b8557a6e283fc71cf39f68d2219a17599c2a6bd62d6c038aaacf10dc003d2408"
}

rule MalwareBazaar_unknown_043_7e214982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e21498244c5e0c07e45bf188b20fceb745d70470b48f2ea7d8fca87c53ab63c"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 00:31:02"
  condition:
    hash.sha256(0, filesize) == "7e21498244c5e0c07e45bf188b20fceb745d70470b48f2ea7d8fca87c53ab63c"
}

rule MalwareBazaar_unknown_044_27b9bb39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213"
    family = "unknown"
    file_name = "27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213"
    file_type = "unknown"
    first_seen = "2026-08-22 00:27:24"
  condition:
    hash.sha256(0, filesize) == "27b9bb39d1f69c963f62d748399fb6bdea6315f88d1521ba242015dc9ce25213"
}

rule MalwareBazaar_Mirai_045_5af40e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77"
    family = "Mirai"
    file_name = "5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77.elf"
    file_type = "elf"
    first_seen = "2026-08-22 00:26:03"
  condition:
    hash.sha256(0, filesize) == "5af40e30ab869cd9f82eb06556061c255ca3154debf93f38f776d853b8f08d77"
}

rule MalwareBazaar_Mirai_046_a157b86b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a157b86bb50b92c090fc69d53330f09f4e9cba5ad3f6d071cce6c541969d08be"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-22 00:15:37"
  condition:
    hash.sha256(0, filesize) == "a157b86bb50b92c090fc69d53330f09f4e9cba5ad3f6d071cce6c541969d08be"
}

rule MalwareBazaar_ValleyRAT_047_755b5972
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "755b59727fa54b89a9e48fe04cc9004a63bfd43d8e55aefc25ce0c825ca6ab6c"
    family = "ValleyRAT"
    file_name = "93BA6A64C60FD088B949BA9B17A6BF5A.dll"
    file_type = "dll"
    first_seen = "2026-08-22 00:15:15"
  condition:
    hash.sha256(0, filesize) == "755b59727fa54b89a9e48fe04cc9004a63bfd43d8e55aefc25ce0c825ca6ab6c"
}

rule MalwareBazaar_RemusStealer_048_18667c13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18667c138b756654501dc2d742285f9795a76209ba3565d07ed6cf11798d3308"
    family = "RemusStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:15:08"
  condition:
    hash.sha256(0, filesize) == "18667c138b756654501dc2d742285f9795a76209ba3565d07ed6cf11798d3308"
}

rule MalwareBazaar_SnappyClient_049_c77dc176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c77dc176b6b643e833ce40829cfbc783b7a0ec317ec12e35095e6523dfb73d8a"
    family = "SnappyClient"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:13:59"
  condition:
    hash.sha256(0, filesize) == "c77dc176b6b643e833ce40829cfbc783b7a0ec317ec12e35095e6523dfb73d8a"
}

rule MalwareBazaar_Mirai_050_a72bef42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a72bef426080975468dc686c7bc44cc99d3574ab626382632921dc48366cf107"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-08-22 00:13:36"
  condition:
    hash.sha256(0, filesize) == "a72bef426080975468dc686c7bc44cc99d3574ab626382632921dc48366cf107"
}

rule MalwareBazaar_SnappyClient_051_3924cc20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3924cc20aef6c2864187f4d5f942056b1f2ac33ab66af6e0ce0985701a3ea091"
    family = "SnappyClient"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:11:32"
  condition:
    hash.sha256(0, filesize) == "3924cc20aef6c2864187f4d5f942056b1f2ac33ab66af6e0ce0985701a3ea091"
}

rule MalwareBazaar_unknown_052_90cd82d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90cd82d7296ca7b11480d47e6e7d94bd69d586a942d39ae8c899bf5df083c46a"
    family = "unknown"
    file_name = "FLStudio2025_v158_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:09:32"
  condition:
    hash.sha256(0, filesize) == "90cd82d7296ca7b11480d47e6e7d94bd69d586a942d39ae8c899bf5df083c46a"
}

rule MalwareBazaar_RemusStealer_053_a3c7d474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c7d47493c861c2cdfe687144fc2a207cf1d10fd1b98c635746f76b8ebe8093"
    family = "RemusStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:08:42"
  condition:
    hash.sha256(0, filesize) == "a3c7d47493c861c2cdfe687144fc2a207cf1d10fd1b98c635746f76b8ebe8093"
}

rule MalwareBazaar_RemusStealer_054_641fcc30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "641fcc308925f0376adb2c30cdf7aa6710c0d227bfc4491fc803cc3efcf4941f"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:07:45"
  condition:
    hash.sha256(0, filesize) == "641fcc308925f0376adb2c30cdf7aa6710c0d227bfc4491fc803cc3efcf4941f"
}

rule MalwareBazaar_unknown_055_974db024
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "974db0246553597676603c5aafa7b1a855dc6bdbbe657d0036470dee1cbc3fea"
    family = "unknown"
    file_name = "libvlc.dll"
    file_type = "exe"
    first_seen = "2026-08-22 00:06:37"
  condition:
    hash.sha256(0, filesize) == "974db0246553597676603c5aafa7b1a855dc6bdbbe657d0036470dee1cbc3fea"
}

rule MalwareBazaar_unknown_056_82085936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82085936272bf263f09cb82c1d9d94c6098f5c46a973d00da4c682346e3fa71e"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-22 00:06:34"
  condition:
    hash.sha256(0, filesize) == "82085936272bf263f09cb82c1d9d94c6098f5c46a973d00da4c682346e3fa71e"
}

rule MalwareBazaar_unknown_057_f80ea3ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043"
    family = "unknown"
    file_name = "f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043"
    file_type = "unknown"
    first_seen = "2026-08-22 00:00:45"
  condition:
    hash.sha256(0, filesize) == "f80ea3ce4bb1bcf1f5893a85255c5f3f2138585630f894d9cbad060ad2da6043"
}

rule MalwareBazaar_unknown_058_b6db146a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866"
    family = "unknown"
    file_name = "b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866"
    file_type = "sh"
    first_seen = "2026-08-21 23:57:33"
  condition:
    hash.sha256(0, filesize) == "b6db146a4318ab09ff1bf9266c208c7523e2e3410ab4635e28df25fc678e6866"
}

rule MalwareBazaar_unknown_059_fd61ded6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5"
    family = "unknown"
    file_name = "fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5"
    file_type = "sh"
    first_seen = "2026-08-21 23:57:31"
  condition:
    hash.sha256(0, filesize) == "fd61ded6fdcedc069c7ace96ab1d5b0d05e1914ab4d20e865ea8af64ec06aee5"
}

rule MalwareBazaar_unknown_060_ea5b8411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5b8411ef37ad40486c019c674565392e10cef6700c707f81284adebcdc157f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 23:52:13"
  condition:
    hash.sha256(0, filesize) == "ea5b8411ef37ad40486c019c674565392e10cef6700c707f81284adebcdc157f"
}

rule MalwareBazaar_DCRat_061_d5aea22b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5aea22bf23f26d0c83d5d96f46f16a4207b69a37956ce975c1b7b2351fcc5cf"
    family = "DCRat"
    file_name = "734F2038EDC0FB655E13004199F9E7DA.exe"
    file_type = "exe"
    first_seen = "2026-08-21 23:50:07"
  condition:
    hash.sha256(0, filesize) == "d5aea22bf23f26d0c83d5d96f46f16a4207b69a37956ce975c1b7b2351fcc5cf"
}

rule MalwareBazaar_unknown_062_768a14a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7"
    family = "unknown"
    file_name = "768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7.exe"
    file_type = "exe"
    first_seen = "2026-08-21 23:46:17"
  condition:
    hash.sha256(0, filesize) == "768a14a6c0c4f8ea3ea8267931da827ffeac67b8cff42e6f28e09d99acd428d7"
}

rule MalwareBazaar_unknown_063_086f204a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5"
    family = "unknown"
    file_name = "086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5"
    file_type = "sh"
    first_seen = "2026-08-21 23:29:46"
  condition:
    hash.sha256(0, filesize) == "086f204a2f6f84c20f95ad67046a3f2742f262783b39e98480537aea9461a7b5"
}

rule MalwareBazaar_unknown_064_98cbbf4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5"
    family = "unknown"
    file_name = "98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5"
    file_type = "unknown"
    first_seen = "2026-08-21 23:21:00"
  condition:
    hash.sha256(0, filesize) == "98cbbf4ceb2d1281732147a5cddf9105be6748ca1d4baa1602444c24e164cec5"
}

rule MalwareBazaar_unknown_065_e668d8fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd"
    family = "unknown"
    file_name = "e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd"
    file_type = "unknown"
    first_seen = "2026-08-21 23:20:59"
  condition:
    hash.sha256(0, filesize) == "e668d8fcccd5362e0964920ddeabf0b1ad354afd25822960fddfb3a6e3b290bd"
}

rule MalwareBazaar_unknown_066_9420e279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a"
    family = "unknown"
    file_name = "9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a"
    file_type = "unknown"
    first_seen = "2026-08-21 23:20:57"
  condition:
    hash.sha256(0, filesize) == "9420e279446ceec7cd0d1d5fcb763d85f77bd939a35a30789e4e8e957d8d342a"
}

rule MalwareBazaar_unknown_067_d96c6de7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5"
    family = "unknown"
    file_name = "d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5"
    file_type = "sh"
    first_seen = "2026-08-21 23:20:56"
  condition:
    hash.sha256(0, filesize) == "d96c6de7ab6abc18381dca34117d891f5826825e6f435e044534ce76120924c5"
}

rule MalwareBazaar_ValleyRAT_068_f42c77fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42c77fc05af60b8e702ab357714890d2ce17419d63bcc108f00be7733e8c7c5"
    family = "ValleyRAT"
    file_name = "480F7E5181F67F318948AE9D304BC06F.dll"
    file_type = "dll"
    first_seen = "2026-08-21 23:10:16"
  condition:
    hash.sha256(0, filesize) == "f42c77fc05af60b8e702ab357714890d2ce17419d63bcc108f00be7733e8c7c5"
}

rule MalwareBazaar_unknown_069_466bb259
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3"
    family = "unknown"
    file_name = "466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3"
    file_type = "sh"
    first_seen = "2026-08-21 23:00:18"
  condition:
    hash.sha256(0, filesize) == "466bb2599b3522d0b8ca2325d54b0849e753ce92f831fc18a0377416728190d3"
}

rule MalwareBazaar_unknown_070_d7437869
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41"
    family = "unknown"
    file_name = "d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41"
    file_type = "sh"
    first_seen = "2026-08-21 22:57:45"
  condition:
    hash.sha256(0, filesize) == "d7437869437f3b9508d4591b05d4ebfb04fbe54fcc15b3a1e9bc1a9f04cf6d41"
}

rule MalwareBazaar_unknown_071_b3b49920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3b4992027e7e6999f891d0152b1e86e986f4518397696a2bc189d21ab78f018"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 22:52:11"
  condition:
    hash.sha256(0, filesize) == "b3b4992027e7e6999f891d0152b1e86e986f4518397696a2bc189d21ab78f018"
}

rule MalwareBazaar_unknown_072_74e64591
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c"
    family = "unknown"
    file_name = "74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c"
    file_type = "unknown"
    first_seen = "2026-08-21 22:27:02"
  condition:
    hash.sha256(0, filesize) == "74e6459121f80d5cef0ab9e1bad20d7354df9874a6f448cb2a1ba860faca5f9c"
}

rule MalwareBazaar_unknown_073_15c1d1f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765"
    family = "unknown"
    file_name = "15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765"
    file_type = "sh"
    first_seen = "2026-08-21 22:27:00"
  condition:
    hash.sha256(0, filesize) == "15c1d1f3ac0418a3c6b4af36a3578322ef39c0a6970b7d1bf69e9a2dc6cb4765"
}

rule MalwareBazaar_unknown_074_06bcf8b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06bcf8b6ba6a3cf02571bb94c135453b70a76fdd6e5ecf55f9fd384efaa8e308"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 22:22:17"
  condition:
    hash.sha256(0, filesize) == "06bcf8b6ba6a3cf02571bb94c135453b70a76fdd6e5ecf55f9fd384efaa8e308"
}

rule MalwareBazaar_unknown_075_f054b071
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f054b071032e81ea59a4ecfbbaa8e8fd080bca0a9ad50c44b9c9772172de7bf5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-21 21:52:12"
  condition:
    hash.sha256(0, filesize) == "f054b071032e81ea59a4ecfbbaa8e8fd080bca0a9ad50c44b9c9772172de7bf5"
}

rule MalwareBazaar_unknown_076_d8df49c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8df49c39fc031f2f460f2bd632c43ac8c8f2aa27ca319ecd9ff259e2eca3768"
    family = "unknown"
    file_name = "stego_jxdqj7fw9j.png"
    file_type = "unknown"
    first_seen = "2026-08-21 21:51:48"
  condition:
    hash.sha256(0, filesize) == "d8df49c39fc031f2f460f2bd632c43ac8c8f2aa27ca319ecd9ff259e2eca3768"
}

rule MalwareBazaar_unknown_077_dc7153a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc7153a7ed6e0c9666de705d53416c62eda0d0c879d6da9a108e282c529cebef"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:51:31"
  condition:
    hash.sha256(0, filesize) == "dc7153a7ed6e0c9666de705d53416c62eda0d0c879d6da9a108e282c529cebef"
}

rule MalwareBazaar_unknown_078_fba26561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba265611c94bd8ce572991abe3437786c7b2b1d8da78dc3e8a825787b3d5a27"
    family = "unknown"
    file_name = "PO 100626-26NB005 086 246-2 254 -ZOLANO,Stokes,Woolworth-SHANTOU-FULL.DEP.BAL- $51,496.86.js"
    file_type = "js"
    first_seen = "2026-08-21 21:47:46"
  condition:
    hash.sha256(0, filesize) == "fba265611c94bd8ce572991abe3437786c7b2b1d8da78dc3e8a825787b3d5a27"
}

rule MalwareBazaar_Mirai_079_563512cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "563512cbc00ac478207d204bf4fd686a533cfa7d8a3948c6d7ba94fb08716fa1"
    family = "Mirai"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-08-21 21:42:38"
  condition:
    hash.sha256(0, filesize) == "563512cbc00ac478207d204bf4fd686a533cfa7d8a3948c6d7ba94fb08716fa1"
}

rule MalwareBazaar_Mirai_080_41893949
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4189394952c2876eab70eb7ce743fd3e7e7d72189045c10197059611f2a4da76"
    family = "Mirai"
    file_name = "dlr.arm"
    file_type = "elf"
    first_seen = "2026-08-21 21:37:33"
  condition:
    hash.sha256(0, filesize) == "4189394952c2876eab70eb7ce743fd3e7e7d72189045c10197059611f2a4da76"
}

rule MalwareBazaar_Mirai_081_2622d2ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2622d2ab4694ba71c9c7970f664d623e94fa11af0159784c40a0538329538f53"
    family = "Mirai"
    file_name = "dlr.x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 21:35:42"
  condition:
    hash.sha256(0, filesize) == "2622d2ab4694ba71c9c7970f664d623e94fa11af0159784c40a0538329538f53"
}

rule MalwareBazaar_Mirai_082_2320a452
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2320a4529e5fddb64858e986cbb269062b8b0d1a0a360fa90e293c1e246166bf"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 21:30:31"
  condition:
    hash.sha256(0, filesize) == "2320a4529e5fddb64858e986cbb269062b8b0d1a0a360fa90e293c1e246166bf"
}

rule MalwareBazaar_Mirai_083_4e5bbea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e5bbea0ace9f3b808161896edcaf620c632385f74855174baff669af3dc9140"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-21 21:30:02"
  condition:
    hash.sha256(0, filesize) == "4e5bbea0ace9f3b808161896edcaf620c632385f74855174baff669af3dc9140"
}

rule MalwareBazaar_Mirai_084_3944defd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3944defd9ed83e169d456ec5422aaaa5ba1882a632f02cc4b40e0d52406ccfd3"
    family = "Mirai"
    file_name = "dlr.ppc"
    file_type = "elf"
    first_seen = "2026-08-21 21:28:29"
  condition:
    hash.sha256(0, filesize) == "3944defd9ed83e169d456ec5422aaaa5ba1882a632f02cc4b40e0d52406ccfd3"
}

rule MalwareBazaar_Mirai_085_19dc8ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19dc8ef01a3671d43868d90d36f625ab881359d2d49e7e4a8ee9bbeb9cd556f9"
    family = "Mirai"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-08-21 21:26:35"
  condition:
    hash.sha256(0, filesize) == "19dc8ef01a3671d43868d90d36f625ab881359d2d49e7e4a8ee9bbeb9cd556f9"
}

rule MalwareBazaar_Mirai_086_75da2ad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75da2ad869488ae22f7adae7dc72a33ca415e8f91578d00eda9d70222d1b02af"
    family = "Mirai"
    file_name = "dlr.spc"
    file_type = "elf"
    first_seen = "2026-08-21 21:24:33"
  condition:
    hash.sha256(0, filesize) == "75da2ad869488ae22f7adae7dc72a33ca415e8f91578d00eda9d70222d1b02af"
}

rule MalwareBazaar_Mirai_087_2410b4ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2410b4ca59e2f8b6272118e0478357c8ac6889678f26ae85c2a07f6c451d6652"
    family = "Mirai"
    file_name = "dlr.m68k"
    file_type = "elf"
    first_seen = "2026-08-21 21:24:32"
  condition:
    hash.sha256(0, filesize) == "2410b4ca59e2f8b6272118e0478357c8ac6889678f26ae85c2a07f6c451d6652"
}

rule MalwareBazaar_Mirai_088_3d24252d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d24252d5fba5a20879ed518a37994f2268bc463d9cfb2995f6e6521eb94e965"
    family = "Mirai"
    file_name = "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af.elf"
    file_type = "elf"
    first_seen = "2026-08-21 21:22:19"
  condition:
    hash.sha256(0, filesize) == "3d24252d5fba5a20879ed518a37994f2268bc463d9cfb2995f6e6521eb94e965"
}

rule MalwareBazaar_Mirai_089_e405bcbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af"
    family = "Mirai"
    file_name = "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af.elf"
    file_type = "elf"
    first_seen = "2026-08-21 21:21:11"
  condition:
    hash.sha256(0, filesize) == "e405bcbf4e1b8a8b135ae22f6d59a2e2f5736f35c514cd1527c8e2c8e40b55af"
}

rule MalwareBazaar_Mirai_090_e448e02e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e448e02e582c8a4746204b93ebeb0545515b2aede8e5bd789fd7ec6ce06c0c03"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-21 21:17:17"
  condition:
    hash.sha256(0, filesize) == "e448e02e582c8a4746204b93ebeb0545515b2aede8e5bd789fd7ec6ce06c0c03"
}

rule MalwareBazaar_Mirai_091_0cca6c20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cca6c20b4466d2db1fb8427ca21c85cdd7c1c460554112f0a238a3d594b2a0e"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-21 21:16:39"
  condition:
    hash.sha256(0, filesize) == "0cca6c20b4466d2db1fb8427ca21c85cdd7c1c460554112f0a238a3d594b2a0e"
}

rule MalwareBazaar_RemusStealer_092_16ba5736
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16ba5736f615fbb3c7a9861c6de1dac8b9eb6757ae815786306ed4f6c6b7bc4f"
    family = "RemusStealer"
    file_name = "1e15f05977d0d5ddde505be77dd3b2ef.exe"
    file_type = "exe"
    first_seen = "2026-08-21 21:15:14"
  condition:
    hash.sha256(0, filesize) == "16ba5736f615fbb3c7a9861c6de1dac8b9eb6757ae815786306ed4f6c6b7bc4f"
}

rule MalwareBazaar_CoinMiner_093_0a3f4115
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a3f4115a9495dca557abff7445aec5d7773906fd91a0b2060f32c2cb42ad8b7"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:12:23"
  condition:
    hash.sha256(0, filesize) == "0a3f4115a9495dca557abff7445aec5d7773906fd91a0b2060f32c2cb42ad8b7"
}

rule MalwareBazaar_unknown_094_b28bdb38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b28bdb3846a844a25300d1f595da9339cc8e5f830312d55bc15ffed6e2c0bd88"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:12:16"
  condition:
    hash.sha256(0, filesize) == "b28bdb3846a844a25300d1f595da9339cc8e5f830312d55bc15ffed6e2c0bd88"
}

rule MalwareBazaar_unknown_095_d5ace966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5ace966356f153320ee9442332fbf3e35e89fe8b217c4a27707d9406b7e14a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:12:06"
  condition:
    hash.sha256(0, filesize) == "d5ace966356f153320ee9442332fbf3e35e89fe8b217c4a27707d9406b7e14a4"
}

rule MalwareBazaar_Mirai_096_82f64f6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82f64f6ba04dd9ee1d96ad0198db8b6b55a83b301a9f099692280b7996850e76"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-21 21:09:20"
  condition:
    hash.sha256(0, filesize) == "82f64f6ba04dd9ee1d96ad0198db8b6b55a83b301a9f099692280b7996850e76"
}

rule MalwareBazaar_Mirai_097_ae0adf86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0adf8657f3b3f1f54a0d2f83f4eca7281c96cb61eb5d053cf239b1a7ded26a"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-21 21:08:30"
  condition:
    hash.sha256(0, filesize) == "ae0adf8657f3b3f1f54a0d2f83f4eca7281c96cb61eb5d053cf239b1a7ded26a"
}

rule MalwareBazaar_unknown_098_81eb84e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81eb84e7cebbfc48853bf4dda7525fb3b21b5014a845d13784f441cda8264906"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-08-21 21:04:42"
  condition:
    hash.sha256(0, filesize) == "81eb84e7cebbfc48853bf4dda7525fb3b21b5014a845d13784f441cda8264906"
}

rule MalwareBazaar_unknown_099_d5309eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5309edae0b8fcb08ddaa46704ff1199ded4b235c5ae40ef53fd6767f124c008"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-21 21:02:21"
  condition:
    hash.sha256(0, filesize) == "d5309edae0b8fcb08ddaa46704ff1199ded4b235c5ae40ef53fd6767f124c008"
}

rule MalwareBazaar_unknown_100_f5c0fabb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092"
    family = "unknown"
    file_name = "f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092"
    file_type = "elf"
    first_seen = "2026-08-21 21:00:21"
  condition:
    hash.sha256(0, filesize) == "f5c0fabbc05edbd7c3836c955b7935364a065c00eed5066473e707de068da092"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

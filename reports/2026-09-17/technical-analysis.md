# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-17

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 619 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 619 |
| Unique family labels | 7 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 73 |
| Mirai | 14 |
| JOMANGY | 9 |
| Prometei | 1 |
| GuLoader | 1 |
| Mozi | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 43 |
| elf | 31 |
| sh | 18 |
| unknown | 4 |
| js | 1 |
| msi | 1 |
| vbs | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `b5a68536fe392178`

| Field | Value |
|---|---|
| SHA-256 | `b5a68536fe3921788dd64d9e792eeac5cdd4b25e50cec28d9598efaf7452e1a9` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-17 04:55:35` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fcac254d513c0db7477c25cd12934e7` |
| SHA-1 | `aebcbde4fe342e9051e4bdee51c348ecdb20f2a9` |
| SHA-256 | `b5a68536fe3921788dd64d9e792eeac5cdd4b25e50cec28d9598efaf7452e1a9` |
| SHA3-384 | `7f5e964f6aad93a567ab089d550d1e206ebfeb481cb9665d4b6ab9b89f301310bdda1183b034df6fd559fb9b7a918485` |
| TLSH | `T1C7136D6566953C24AE9988371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:jXRWNGxVc9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:dlxbco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_001_b5a68536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5a68536fe3921788dd64d9e792eeac5cdd4b25e50cec28d9598efaf7452e1a9"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 04:55:35"
  condition:
    hash.sha256(0, filesize) == "b5a68536fe3921788dd64d9e792eeac5cdd4b25e50cec28d9598efaf7452e1a9"
}
```

### Sample 2: `6563b04cdd56bed1`

| Field | Value |
|---|---|
| SHA-256 | `6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779` |
| Family label | `unknown` |
| File name | `6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779.sh` |
| File type | `sh` |
| First seen | `2026-09-17 04:52:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f09d5b52eceb5ba9d46bffdf49ca9071` |
| SHA-1 | `72b887508effbb922a71280e43cccac556351290` |
| SHA-256 | `6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779` |
| SHA3-384 | `c3d4376f2abd15536dfe9cf03781d13e1da5b9be928c9cd41e57c16417a20180a388af752c87f8eb62b0591320173609` |
| TLSH | `T18762567720F08B3397D425C8A2775A614EB2965B446224B9F4FE57399F1DB03B0EBB20` |
| SSDEEP | `192:cCua6S4hvZ5mN9i/KNpivzt8ZVOyu/+zfvsMQ+j:gS4hvZ5mN9i/KNpivA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_6563b04c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779"
    family = "unknown"
    file_name = "6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779.sh"
    file_type = "sh"
    first_seen = "2026-09-17 04:52:33"
  condition:
    hash.sha256(0, filesize) == "6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779"
}
```

### Sample 3: `6ed67e01f2dfeb56`

| Field | Value |
|---|---|
| SHA-256 | `6ed67e01f2dfeb56f26811658a81982e3106baaee2031abeac604c2b309152c0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 04:47:15` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76eb0e6bb8dd327a30a432f932118302` |
| SHA-1 | `739e97f7d006aa19ccbe8e5032003dfb8a5f1109` |
| SHA-256 | `6ed67e01f2dfeb56f26811658a81982e3106baaee2031abeac604c2b309152c0` |
| SHA3-384 | `710731c9fb0a615bf73b7c4dbcd8b150403352f2ac677047a6ed28af213194357c79efd253ad9e452b156fad8b64e488` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13A62E7C6E9961FACDE8E80703A12F878BDB53291866559F7D7D29C305EA38C10424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U51mXe:fKOe2/7c9sN3zfZR1m+RGgq6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_6ed67e01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ed67e01f2dfeb56f26811658a81982e3106baaee2031abeac604c2b309152c0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:47:15"
  condition:
    hash.sha256(0, filesize) == "6ed67e01f2dfeb56f26811658a81982e3106baaee2031abeac604c2b309152c0"
}
```

### Sample 4: `96fe80312f79e679`

| Field | Value |
|---|---|
| SHA-256 | `96fe80312f79e679655922b0a93fd3794f6c6e8f9140c1e60abbd55257df1155` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 04:44:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89310a42ea0154ee145612919e2a40ba` |
| SHA-1 | `970c12acc7df8823d676809e5cdccebef5e80faa` |
| SHA-256 | `96fe80312f79e679655922b0a93fd3794f6c6e8f9140c1e60abbd55257df1155` |
| SHA3-384 | `6d2075e8627b121a56ea23ec70cff73277c5c06f43a780876372dcbfe5b09c10c0e634b0410960b35971dd4e1e76f47f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CA62E886E9921F5CCE4F80703A11F938697632949A6959E7D7928C704EBBAD00438FFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGlooooooooooooooooooooooooI6C:fKOeOQOzUxloooooooooooooooooooo5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_96fe8031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96fe80312f79e679655922b0a93fd3794f6c6e8f9140c1e60abbd55257df1155"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:44:49"
  condition:
    hash.sha256(0, filesize) == "96fe80312f79e679655922b0a93fd3794f6c6e8f9140c1e60abbd55257df1155"
}
```

### Sample 5: `851cf00451adf72a`

| Field | Value |
|---|---|
| SHA-256 | `851cf00451adf72a80fc5d6c23db0024e2c98e371cff3e149af91a1473b5fd92` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 04:42:23` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d12c3e2ba4a5d16d91452cb5f25e28b1` |
| SHA-1 | `4d0e11e88d4e18c555c65363e66a00adf031481e` |
| SHA-256 | `851cf00451adf72a80fc5d6c23db0024e2c98e371cff3e149af91a1473b5fd92` |
| SHA3-384 | `1ff6040901b6ad59364c1395cc39ad59374a9fba758b10524d6f3f598a8caed226c727e19436689272fc71f42b4d88f9` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13362D88ADAD22E7CCE4E80703B11F978BDB476D48515A9E3D7828C364DA39D01464FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UOm0we:fKOe2/7c9sN3zfZR1m+RGs16C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_851cf004
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "851cf00451adf72a80fc5d6c23db0024e2c98e371cff3e149af91a1473b5fd92"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:42:23"
  condition:
    hash.sha256(0, filesize) == "851cf00451adf72a80fc5d6c23db0024e2c98e371cff3e149af91a1473b5fd92"
}
```

### Sample 6: `c3efcb33f06e3462`

| Field | Value |
|---|---|
| SHA-256 | `c3efcb33f06e34624a1168a60d51f16e4a0c1107d16ba603f7868e62835b5393` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 04:39:29` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4ee78c27f10d9a209346502a8b2cb02` |
| SHA-1 | `f2c7abc0aab0d1769cbf88a33c414f4c985694a4` |
| SHA-256 | `c3efcb33f06e34624a1168a60d51f16e4a0c1107d16ba603f7868e62835b5393` |
| SHA3-384 | `5e44f03c8561581868e6414ddeace1193e0fdf9240ea3d6d0f9d2b482182434ea7bf7c5113e3ce9134f3481cec9e4f83` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19B62D58AD8A25F6CDE4E80713B11FC38BE7576D086266EE3D7928C3459A39D05024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U7yrBM:fKOe2/7c9sN3zfZR1m+RGAyr6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_c3efcb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3efcb33f06e34624a1168a60d51f16e4a0c1107d16ba603f7868e62835b5393"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:39:29"
  condition:
    hash.sha256(0, filesize) == "c3efcb33f06e34624a1168a60d51f16e4a0c1107d16ba603f7868e62835b5393"
}
```

### Sample 7: `7008af80cb565d40`

| Field | Value |
|---|---|
| SHA-256 | `7008af80cb565d40b5c0a05e27d8f68b8596218f7010e8120fcdcbeab855411d` |
| Family label | `unknown` |
| File name | `Kohzan Maru VI Vessel Q88.js` |
| File type | `js` |
| First seen | `2026-09-17 04:38:24` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7200454272d27b494cc2022604e2f450` |
| SHA-1 | `036ca79bd386f3cf0f0af97ffdeda8832d2b6e4e` |
| SHA-256 | `7008af80cb565d40b5c0a05e27d8f68b8596218f7010e8120fcdcbeab855411d` |
| SHA3-384 | `ac93a99ede62b4d2fa37284203e11a75e8c5346fc55c3d319ca0ff366dd21150e14ad7905131f99d103ef0e83184fe92` |
| TLSH | `T1AA92C9545992748453377BBBB32BA8E4F7760AAB00854D07B43CA090AFB2D0DDED0CB9` |
| SSDEEP | `384:C9cry7jiRj1/wxFP3vRTRlxDGWd3CYk7yUvGiNDxOEtQm/u4s2fMc2mvO7+j4nie:C9cr+jir/EFP3vRTRlxDGWhCYk7yUvGN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_7008af80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7008af80cb565d40b5c0a05e27d8f68b8596218f7010e8120fcdcbeab855411d"
    family = "unknown"
    file_name = "Kohzan Maru VI Vessel Q88.js"
    file_type = "js"
    first_seen = "2026-09-17 04:38:24"
  condition:
    hash.sha256(0, filesize) == "7008af80cb565d40b5c0a05e27d8f68b8596218f7010e8120fcdcbeab855411d"
}
```

### Sample 8: `567dbac64a05d549`

| Field | Value |
|---|---|
| SHA-256 | `567dbac64a05d549505a597dcfd357eebd02e9b0b6000371edc43f930ec8052e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 04:36:44` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9927a48a173921d1470e18016b5fcbf` |
| SHA-1 | `fdfd2854a34e0576d60f1d7ba80957754980bf40` |
| SHA-256 | `567dbac64a05d549505a597dcfd357eebd02e9b0b6000371edc43f930ec8052e` |
| SHA3-384 | `3c5876f971d45ad985372749c4cc3a94fb3bf125a1a620eb3d458f5ca12f92d2b6809e127b26b78c73d24ededf45a39d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D862E7C6D9926F9CCE4F90703A21F878A97137998A55A9E3D782CC345DA3AC10424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U6GBgn:fKOe2/7c9sN3zfZR1m+RGm6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_567dbac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "567dbac64a05d549505a597dcfd357eebd02e9b0b6000371edc43f930ec8052e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:36:44"
  condition:
    hash.sha256(0, filesize) == "567dbac64a05d549505a597dcfd357eebd02e9b0b6000371edc43f930ec8052e"
}
```

### Sample 9: `28388aad9b33b0d2`

| Field | Value |
|---|---|
| SHA-256 | `28388aad9b33b0d2ffa985ef62c8e2fa67f2a147475f575caa411cdebebb0b8c` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-09-17 04:34:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b36be3c9bc811adabd0b8679a3a67c42` |
| SHA-1 | `e258f08cd0e131f8320e1c72590a10dda6fb2990` |
| SHA-256 | `28388aad9b33b0d2ffa985ef62c8e2fa67f2a147475f575caa411cdebebb0b8c` |
| SHA3-384 | `4247668441f4b03c705cede7ad7649cd7c8228e918e394f246e09283025136a3f684917cdbb218f217731b32bd288118` |
| TLSH | `T19CF4E713E6024955E6D448F2327A3289BA47537FC5EF3183FD160EA0BE9585B0A7BEC1` |
| TELFHASH | `t117e020601e3670f4bd89918541f56f22b9342541165f1551427edf5c2be78c1a111a0b` |
| SSDEEP | `6144:3ycZP/9hUkljuRAu0AXzk0CaSGwJ+T6+:3ychFhU6juGnAXZCaS1J0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_28388aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28388aad9b33b0d2ffa985ef62c8e2fa67f2a147475f575caa411cdebebb0b8c"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-09-17 04:34:41"
  condition:
    hash.sha256(0, filesize) == "28388aad9b33b0d2ffa985ef62c8e2fa67f2a147475f575caa411cdebebb0b8c"
}
```

### Sample 10: `b5459a6ed51aa6ca`

| Field | Value |
|---|---|
| SHA-256 | `b5459a6ed51aa6ca1536a9f807a12551ce8679ff13d6f6f001706caf6259adaa` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-17 04:34:40` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a92d6d1a8cc4952d131f899c42792458` |
| SHA-1 | `d7de0e0e8b050aebfebaa1bf95091ff39b37da3e` |
| SHA-256 | `b5459a6ed51aa6ca1536a9f807a12551ce8679ff13d6f6f001706caf6259adaa` |
| SHA3-384 | `e28c876ca3ec10febed04eb6bb4aba767b93f3298fb9c1b5f02ae38d07a8727080c1db84f2dac52fa96080d0fdf21eb2` |
| TLSH | `T159136D6926813C289D9998371D7E2F0CB9A983E6310891DCBFCB3CF58C1979DE219719` |
| SSDEEP | `768:HXOGVvc9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:3LZco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_010_b5459a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5459a6ed51aa6ca1536a9f807a12551ce8679ff13d6f6f001706caf6259adaa"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 04:34:40"
  condition:
    hash.sha256(0, filesize) == "b5459a6ed51aa6ca1536a9f807a12551ce8679ff13d6f6f001706caf6259adaa"
}
```

### Sample 11: `1b03ce50b5b6fd1a`

| Field | Value |
|---|---|
| SHA-256 | `1b03ce50b5b6fd1a5368388e5c2243eb30e113029981de2b713fe2d4d3ebbac4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 04:34:28` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fb864e6eae21c64ec377865f924e1ad` |
| SHA-1 | `25cf97470ccb0bebf0ff3adf457b68f7c63469d2` |
| SHA-256 | `1b03ce50b5b6fd1a5368388e5c2243eb30e113029981de2b713fe2d4d3ebbac4` |
| SHA3-384 | `242230dd73e9dbb9549bf211038b8a9aa1525d6b2c50587691ce99fb6f9c3e764bc5336931cf3f070d612453cfb9fece` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E362C786D892AF5CCE4E80707A11F9387DB436948A6959E7DB828C305DA39D0543CFFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UhtMBM:fKOe2/7c9sN3zfZR1m+RGYtM6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_1b03ce50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b03ce50b5b6fd1a5368388e5c2243eb30e113029981de2b713fe2d4d3ebbac4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:34:28"
  condition:
    hash.sha256(0, filesize) == "1b03ce50b5b6fd1a5368388e5c2243eb30e113029981de2b713fe2d4d3ebbac4"
}
```

### Sample 12: `1ab16260eb6253ce`

| Field | Value |
|---|---|
| SHA-256 | `1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09` |
| Family label | `unknown` |
| File name | `1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09.sh` |
| File type | `sh` |
| First seen | `2026-09-17 04:28:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70539fdb5f31c046129872e5df925f56` |
| SHA-1 | `63f4ddf0c668e0e2aa081e0a0958780e74f44ccc` |
| SHA-256 | `1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09` |
| SHA3-384 | `d05b29fcb8dd0389fd6121230ff0639bff5f08b73ac29aae2b9232a04adad7a9f30613bb084553c4a6c6d9631e2783e0` |
| TLSH | `T1D642D57125F24C3339715944B2772BA2ABB6D95385E3328C35CE2E365F86F02B1AF911` |
| SSDEEP | `96:cRuKB6esxC1CUJRxG22lQxfafW5SKSOSCgHSajmYmFZ6AZxCnC/U0:cRuu6evnThW/q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_1ab16260
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09"
    family = "unknown"
    file_name = "1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09.sh"
    file_type = "sh"
    first_seen = "2026-09-17 04:28:40"
  condition:
    hash.sha256(0, filesize) == "1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09"
}
```

### Sample 13: `baf04b1406f12ef2`

| Field | Value |
|---|---|
| SHA-256 | `baf04b1406f12ef26a61367823663e23e8348bb4477adcddf45afd8c91fa43af` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-17 04:25:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99b0ab0ad918ae4542c1ecc6039a2812` |
| SHA-1 | `20b7c43ed485a1bb183bb9392ac8023081dbb963` |
| SHA-256 | `baf04b1406f12ef26a61367823663e23e8348bb4477adcddf45afd8c91fa43af` |
| SHA3-384 | `930a78bfd175ec71a9542f141af75ffc2f33f382e4c077c4cdb73c3d7fc82cbf722a5ebf5e0bedf316d91c4377f9fa23` |
| TLSH | `T116C33A59FD819B11D5C622BBFA1E028A331357ACE3EF72129D205F2537CA96B0E77901` |
| TELFHASH | `t181011e32eb090a1c97e1c008479de034bbb272d827162894cfd9cb8b0806ec1768c834` |
| SSDEEP | `3072:LkUhW6FtxBaE6pcFRaebXQdcXmAULBc0lmPAO:LzhWutxBaORaebXQd+mzBzlkA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_baf04b14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf04b1406f12ef26a61367823663e23e8348bb4477adcddf45afd8c91fa43af"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-17 04:25:47"
  condition:
    hash.sha256(0, filesize) == "baf04b1406f12ef26a61367823663e23e8348bb4477adcddf45afd8c91fa43af"
}
```

### Sample 14: `47e964af9b5509b4`

| Field | Value |
|---|---|
| SHA-256 | `47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd` |
| Family label | `unknown` |
| File name | `47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd` |
| File type | `elf` |
| First seen | `2026-09-17 04:17:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4b14c5d54b541a9636bfc8d33ae590a` |
| SHA-1 | `4076a2279c252ac22c138b988f208d2e048b2138` |
| SHA-256 | `47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd` |
| SHA3-384 | `a0da749758b9daacab30260e8ee02492b5f64f858226645be9c1bf67800dc98626e6cc6635bad0d3920b92d7424fd03c` |
| TLSH | `T165B31249FE319C0B9F000DB71BDA9F9E9C697B6B01DBF4A46AC2944F57A01CD7C52218` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+VM:phNlHuBafLeBtfCzpta8xlBIOdVoX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_47e964af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd"
    family = "unknown"
    file_name = "47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd"
    file_type = "elf"
    first_seen = "2026-09-17 04:17:18"
  condition:
    hash.sha256(0, filesize) == "47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd"
}
```

### Sample 15: `1937a7d65d55cf24`

| Field | Value |
|---|---|
| SHA-256 | `1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466` |
| Family label | `unknown` |
| File name | `1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466` |
| File type | `elf` |
| First seen | `2026-09-17 04:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f75a4cd077634d7195b0e37a45a322e` |
| SHA-1 | `1b38ca1e368ad964a8ba419579ed1f893cc8ad45` |
| SHA-256 | `1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466` |
| SHA3-384 | `75f337ff572865a83fbe46dda2eb17b53478287770d43f6490f1e83555bca89e54828e9f65f614ff3eab30ae114f85a5` |
| TLSH | `T1D383199ABC919A5655D413BBBA7E85CE330323B8D2DF7103CD045F18B6CA94F0E7A582` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DhrPDysX+4if3LEVwjUt87HwJR:T2s/ITo7WCkybotgsJ913DhrbW4UYSxg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_1937a7d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466"
    family = "unknown"
    file_name = "1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466"
    file_type = "elf"
    first_seen = "2026-09-17 04:17:12"
  condition:
    hash.sha256(0, filesize) == "1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466"
}
```

### Sample 16: `c0f2e2e94e578d76`

| Field | Value |
|---|---|
| SHA-256 | `c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44` |
| Family label | `unknown` |
| File name | `c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44.sh` |
| File type | `sh` |
| First seen | `2026-09-17 04:16:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b67721bcb8d40a181b56252f712950e` |
| SHA-1 | `4d2cb04b7e896c2bd3bc8f1baf0c8b01ba06c586` |
| SHA-256 | `c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44` |
| SHA3-384 | `6c3ed6665f13660fc40967d02f9a6b99ac0303185c1670d0d942e09fb477eb2f660de13b125e2debddaa59faf7fd8c6b` |
| TLSH | `T161E1C27125F18D332A24AA80B2372BA6ABB6D95745E721CC35CE2D265F87B11B0FF411` |
| SSDEEP | `96:cLuvzPB65NGr+QC+wN909VM9tQIBvIB6IBDIB7I5XAzAuzA5zAvzAlzA9:cLub56jYRCv+cnQ4fcQFL2SoM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_c0f2e2e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44"
    family = "unknown"
    file_name = "c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44.sh"
    file_type = "sh"
    first_seen = "2026-09-17 04:16:35"
  condition:
    hash.sha256(0, filesize) == "c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44"
}
```

### Sample 17: `15eeb52af2fcc5e6`

| Field | Value |
|---|---|
| SHA-256 | `15eeb52af2fcc5e68ebaf9f059b9afe3917d60b3d727b36a106722a05755e36e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-17 04:13:30` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fc0c0efe9d6a5cea406a89abb394dbb` |
| SHA-256 | `15eeb52af2fcc5e68ebaf9f059b9afe3917d60b3d727b36a106722a05755e36e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_15eeb52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15eeb52af2fcc5e68ebaf9f059b9afe3917d60b3d727b36a106722a05755e36e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-17 04:13:30"
  condition:
    hash.sha256(0, filesize) == "15eeb52af2fcc5e68ebaf9f059b9afe3917d60b3d727b36a106722a05755e36e"
}
```

### Sample 18: `36fa048836371a92`

| Field | Value |
|---|---|
| SHA-256 | `36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb` |
| Family label | `unknown` |
| File name | `36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb.sh` |
| File type | `sh` |
| First seen | `2026-09-17 03:58:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99e8f73f5e5d0b1324739b643933dee4` |
| SHA-1 | `a755fdfd42eea48ddabe1f2a3b6676e916440424` |
| SHA-256 | `36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb` |
| SHA3-384 | `9e5165e59dcf968dc87d1de865ec798a00e9815e23312334c2bc715c7c8c544d0a32d0bd544fcd059a7d151d5752f569` |
| TLSH | `T12332E67025F08D732E25AA80B3372BA5ABB6D95345E7218C35DD2E265F87B12B0FF411` |
| SSDEEP | `96:cCu3k0B6VzYMPZo8zS+6+x+s6IBqHIBZIBcIBSIBrIB4IBNIBrIBF9zbDfBWzAF5:cCu0g6VjZYBe4Tm/9g/C4EI0XxUWRhfp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_36fa0488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb"
    family = "unknown"
    file_name = "36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:58:45"
  condition:
    hash.sha256(0, filesize) == "36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb"
}
```

### Sample 19: `d26f403f40ee4a05`

| Field | Value |
|---|---|
| SHA-256 | `d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a` |
| Family label | `unknown` |
| File name | `d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a.sh` |
| File type | `sh` |
| First seen | `2026-09-17 03:58:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a38014fbf7535271303f926e072ca74` |
| SHA-1 | `0455c8b70e28ff29292bafde647562c6626a1faf` |
| SHA-256 | `d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a` |
| SHA3-384 | `a40efe76d0a55e4f61e0e9f01089b148189a96437ebc70d946e05f38223cb33ad340cb5227c21c049271b45842783a9c` |
| TLSH | `T10732587B21F08B32D3D011C962775A614F71A70B456614B8F4BE673AAF2DA0371E7B21` |
| SSDEEP | `96:cCuOiB657sht+O+v1fsn+h4+tIicqbA/GsGCuKNppjrwaTN1COlkZECx2x5W:cCuT65C4hvZ5mzjqKNpu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_d26f403f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a"
    family = "unknown"
    file_name = "d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:58:43"
  condition:
    hash.sha256(0, filesize) == "d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a"
}
```

### Sample 20: `bbd040d2e5b982d2`

| Field | Value |
|---|---|
| SHA-256 | `bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb` |
| Family label | `unknown` |
| File name | `bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb.sh` |
| File type | `sh` |
| First seen | `2026-09-17 03:54:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d0e951ffc01fe07d1a8fe6372fb3570` |
| SHA-1 | `d7266f80e3436df783a9381e7b06485df9eb4ec4` |
| SHA-256 | `bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb` |
| SHA3-384 | `b15341512278150d91f14871219195c5d5d550617fa63a19169439b57978fed486e55d8afad34cad7b7a0048cf1ac6ef` |
| TLSH | `T17032473B21F08B32D3D010C962B61B654F72A70B456614B5F4BE6736AF2DA0371E7B61` |
| SSDEEP | `96:cCuO3B6csht+O+v1fsn+h4+tIiKqCTyOysYtujtuHKNpUj4waHv6+VzAJzADzAdH:cCuG6p4hvZ5m5FG4j4HKNphvF88ifz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_bbd040d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb"
    family = "unknown"
    file_name = "bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:54:26"
  condition:
    hash.sha256(0, filesize) == "bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb"
}
```

### Sample 21: `41baa062d7079b95`

| Field | Value |
|---|---|
| SHA-256 | `41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09` |
| Family label | `unknown` |
| File name | `41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09.sh` |
| File type | `sh` |
| First seen | `2026-09-17 03:54:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90c0ddfbab4fb26f49f2be2ade3e6cb8` |
| SHA-1 | `d7194a06e91e00480caf14bffe70b81af4da56fc` |
| SHA-256 | `41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09` |
| SHA3-384 | `c8bd9c80fd04925d20918e5fdbdb4ad5d2ad7f935f8d4855dba1ed4f63463fea6c67fc7cce73fc3d31785784287c72c1` |
| TLSH | `T18242453721F08B3297D065C4A2771BA14FB2970B456714B8F4FE5A269F6DA0370EBB21` |
| SSDEEP | `96:cCuGB6n7sht+O+v1fsn+h4+tIicqbA/GsGCuKNppjrwaV+I+j+3+FIBmIBGIBXnx:cCuq6nC4hvZ5mzjqKNpHPQsmJ1Q0Rg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_41baa062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09"
    family = "unknown"
    file_name = "41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:54:24"
  condition:
    hash.sha256(0, filesize) == "41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09"
}
```

### Sample 22: `de4940e9d5d87a13`

| Field | Value |
|---|---|
| SHA-256 | `de4940e9d5d87a133b2a5ae127630f6db7d92c289eed77298ef8d319fc986c50` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-17 03:54:23` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8408f1974cccc7b9f4bcd2747afdea6f` |
| SHA-1 | `2de3233db30c43aea9298087bf1c06547a1f24fa` |
| SHA-256 | `de4940e9d5d87a133b2a5ae127630f6db7d92c289eed77298ef8d319fc986c50` |
| SHA3-384 | `63fb9e108f4e35a63612b0b871d7e951cf5ea51b241c1c9b183c3db905f30c579abe4c5beb56e227e47e41569e9d00f3` |
| TLSH | `T1ABC27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:n8vCB+25j6es8Rq9FYpMSUpi+20qUpi+20YQX:n8l25Jcd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_022_de4940e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de4940e9d5d87a133b2a5ae127630f6db7d92c289eed77298ef8d319fc986c50"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-17 03:54:23"
  condition:
    hash.sha256(0, filesize) == "de4940e9d5d87a133b2a5ae127630f6db7d92c289eed77298ef8d319fc986c50"
}
```

### Sample 23: `98de96dc2fbd79e2`

| Field | Value |
|---|---|
| SHA-256 | `98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0` |
| Family label | `unknown` |
| File name | `98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0.sh` |
| File type | `sh` |
| First seen | `2026-09-17 03:49:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4964da70645c4d0c49b6756786606d6b` |
| SHA-1 | `2f88354f27a5e25441b6c39054bd79ccec7d0924` |
| SHA-256 | `98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0` |
| SHA3-384 | `5a2e0f41d65b3d64119c0372e8cd0d90418ed4fe12fd070edb661a774aa0d3606718489b32bd42776a50eb2af2d8aa7b` |
| TLSH | `T12F42357721F08B3297C055C8A2771B614F72970B456714B8F4BE5B2A9F2DA0370EBB61` |
| SSDEEP | `96:cCu3k0B6n7sht+O+v1fsn+h4+tIicqbA/GsGCuKNppjrwaaIBRIB0IBT7IBbVzbu:cCu0g6nC4hvZ5mzjqKNp02LG7Uixm+T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_98de96dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0"
    family = "unknown"
    file_name = "98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:49:33"
  condition:
    hash.sha256(0, filesize) == "98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0"
}
```

### Sample 24: `34431659c7b37339`

| Field | Value |
|---|---|
| SHA-256 | `34431659c7b37339b7d9774204d55b4fc68d3e970eaa76056e8be11d6eec7780` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-09-17 03:49:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02a552f8960763df9eb89432b4cd5a6b` |
| SHA-1 | `d5c148a3e56a59aee7298a1abe490efb41e7d389` |
| SHA-256 | `34431659c7b37339b7d9774204d55b4fc68d3e970eaa76056e8be11d6eec7780` |
| SHA3-384 | `aca89a5bceb0f05e75d3460ef02eb28fde2450a9cad139597052907c500ea0c23763d07515ccb5da0f07cf1d39022acb` |
| TLSH | `T1A1F4C513E6160855E6D848F2327A3288BE5753BFC5EB3183FD160E90BE9581B0A77ED1` |
| TELFHASH | `t17121f4c4df840aa8bbf645a9829db03149fd356e9f293993ca19af2f5c039c1f415c13` |
| SSDEEP | `6144:Atvn89M2+pQhhFhGy15OCyXBE4ysVYvWraifq59:AFnUR+pQhhr5OCyRE4Vmur9S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_34431659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34431659c7b37339b7d9774204d55b4fc68d3e970eaa76056e8be11d6eec7780"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-09-17 03:49:32"
  condition:
    hash.sha256(0, filesize) == "34431659c7b37339b7d9774204d55b4fc68d3e970eaa76056e8be11d6eec7780"
}
```

### Sample 25: `9dd565d2bb8a2e4f`

| Field | Value |
|---|---|
| SHA-256 | `9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9` |
| Family label | `unknown` |
| File name | `9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9` |
| File type | `elf` |
| First seen | `2026-09-17 03:17:35` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ce626989d130711bf0590e36848b256` |
| SHA-1 | `a1ab3f1fe430ea704b31b4e7de375e49f6b218c9` |
| SHA-256 | `9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9` |
| SHA3-384 | `76514a6eca14ddea52c4ae38aaf288e0a31fc3594fd0ef17e79f208f796641e8efa2cea8cd3043d7f5d51281980329cf` |
| TLSH | `T109D67C77914238E9E5A98CB4D11025426DBC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQj:cqYUQuVDt0TZEU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_9dd565d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9"
    family = "unknown"
    file_name = "9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:35"
  condition:
    hash.sha256(0, filesize) == "9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9"
}
```

### Sample 26: `d722a46e3c3acfd1`

| Field | Value |
|---|---|
| SHA-256 | `d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c` |
| Family label | `unknown` |
| File name | `d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c` |
| File type | `elf` |
| First seen | `2026-09-17 03:17:27` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6928d7dc478564a75171d3a9820ea984` |
| SHA-1 | `052aa91c606b56214bf7d5176528d2719afd9a10` |
| SHA-256 | `d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c` |
| SHA3-384 | `0235c827afefa57734e320daaa3901ebd61aaa2f232ba57b1d30ea03e245ee471f19a013128dc90c482734a45138d666` |
| TLSH | `T1A7C3124AFF329C1ADF402DB22ADB5E8E9C6D7A5B41CBF4A878C1D18F47901CD7A52214` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ1J:p3lOYoaja8xzx/0wsxzJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_d722a46e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c"
    family = "unknown"
    file_name = "d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:27"
  condition:
    hash.sha256(0, filesize) == "d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c"
}
```

### Sample 27: `05c667f45f5df631`

| Field | Value |
|---|---|
| SHA-256 | `05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e` |
| Family label | `unknown` |
| File name | `05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e` |
| File type | `elf` |
| First seen | `2026-09-17 03:17:20` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cc637b08cf5cd04468de62e80e20ab3` |
| SHA-1 | `25fd54fc5ab58d1978dc72af5d62c367c30c2516` |
| SHA-256 | `05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e` |
| SHA3-384 | `901b4a170fa863169fbfae34a104834c6212476907cc4c15d0e3332050bef532f7d8c74074170ac3bed5c4d5237e6c2b` |
| TLSH | `T17CD31312D3130C4FC42578F97E2BE61929862E7924CE409C46F6D66A5FB70C8EDB1713` |
| SSDEEP | `3072:biMYFJvw6Yh0b1gKobtCGCmCRlrisfrY6:fYFJvwe1gKCYVl2szh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_05c667f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e"
    family = "unknown"
    file_name = "05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:20"
  condition:
    hash.sha256(0, filesize) == "05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e"
}
```

### Sample 28: `10b55876b694b625`

| Field | Value |
|---|---|
| SHA-256 | `10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560` |
| Family label | `Mirai` |
| File name | `10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560` |
| File type | `elf` |
| First seen | `2026-09-17 03:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5e49f9c802e4db69c78cc8db901d59c` |
| SHA-1 | `bc88ac6ad0b9e72054a3a3b5f6ee9ab566c72fad` |
| SHA-256 | `10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560` |
| SHA3-384 | `8ccdda2f824a158714b03f97d97587497bdfa0b21fa6a41d6d28b19f00bcc48da3870f9e35b6b844af2eafc9a7ed302e` |
| TLSH | `T1B244398AFD80AF25D5C5227BFE2F428A331317B8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_10b55876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560"
    family = "Mirai"
    file_name = "10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:14"
  condition:
    hash.sha256(0, filesize) == "10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560"
}
```

### Sample 29: `775678b3536af460`

| Field | Value |
|---|---|
| SHA-256 | `775678b3536af460c08b77224d540d909a946409f40ee0db03eb1f8d35e9c4b7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-17 03:13:14` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbe02a85d75b16d2610abe454c69f8c4` |
| SHA-256 | `775678b3536af460c08b77224d540d909a946409f40ee0db03eb1f8d35e9c4b7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_775678b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "775678b3536af460c08b77224d540d909a946409f40ee0db03eb1f8d35e9c4b7"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-17 03:13:14"
  condition:
    hash.sha256(0, filesize) == "775678b3536af460c08b77224d540d909a946409f40ee0db03eb1f8d35e9c4b7"
}
```

### Sample 30: `004603a25e2e2725`

| Field | Value |
|---|---|
| SHA-256 | `004603a25e2e27251b14d62c726d3333da05a0f49d90f7fbe444b2868733dc82` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-17 03:09:40` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `365ac68f005891a55aabaded1a6cbb85` |
| SHA-1 | `e5996a2360b2ab09968232940ce92751691fe467` |
| SHA-256 | `004603a25e2e27251b14d62c726d3333da05a0f49d90f7fbe444b2868733dc82` |
| SHA3-384 | `f17c76fa3462a6d608d3888dad31c0feda283af03c0805a878f8963070b542737545ab5769e04ca58297e124bf0511aa` |
| TLSH | `T1DF137D6966857C24AE99883B1C7E2F0CB9A983E1310451DDBFCB3CF58C49ADCD21971D` |
| SSDEEP | `768:e+fh9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:e+fKco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_030_004603a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "004603a25e2e27251b14d62c726d3333da05a0f49d90f7fbe444b2868733dc82"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 03:09:40"
  condition:
    hash.sha256(0, filesize) == "004603a25e2e27251b14d62c726d3333da05a0f49d90f7fbe444b2868733dc82"
}
```

### Sample 31: `9db957aab489232f`

| Field | Value |
|---|---|
| SHA-256 | `9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5` |
| Family label | `unknown` |
| File name | `9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5` |
| File type | `elf` |
| First seen | `2026-09-17 02:52:32` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61bbb58b5c32d1cf72f5a438a36d947e` |
| SHA-1 | `90e23d8b924f7217760ed3ff6d245ad882e9ad73` |
| SHA-256 | `9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5` |
| SHA3-384 | `09fd73b38a4b6d25cb734686322ceb99e826d02996fa93d57d2e975578fe0aaeb761ca57d87fc93315bbb9f14215c79d` |
| TLSH | `T1C7B33901F742EBB4E68318F1487BE724FF354D1F026088EBFBC166B07991A9158E665E` |
| TELFHASH | `t1d411ced4d73071b89732c1fad2b0e0797979838c93a09a64816ab3731d4e8c59016003` |
| SSDEEP | `1536:zXrNgHgiazHcx6Xm53kReH5HUrpF/X0VtvmUeqLkokJwIo54ZHYQT33q7KzFVll9:zb6giaABk7FduQwMWQT33q7MkS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_9db957aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5"
    family = "unknown"
    file_name = "9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5"
    file_type = "elf"
    first_seen = "2026-09-17 02:52:32"
  condition:
    hash.sha256(0, filesize) == "9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5"
}
```

### Sample 32: `dc8caaee7a1fd32f`

| Field | Value |
|---|---|
| SHA-256 | `dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102` |
| Family label | `Prometei` |
| File name | `dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102` |
| File type | `elf` |
| First seen | `2026-09-17 02:51:41` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f61b199220cbe58fc75fef2bab617668` |
| SHA-1 | `108c79adfafea1bf16385c1d1716c536e801c75d` |
| SHA-256 | `dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102` |
| SHA3-384 | `3f6f935f11b979929b701eb4d0ef4ea4a248bbff3ba2de688aa29fbbf375ef2d436191683b350e012c448411eb3559b4` |
| TLSH | `T1F8A423B4F9219E8F6DD769B91B24C31DE182C172689D4C1313AE94E34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdw:Fs6pyCC/Ya2hpi6T6N4e` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_032_dc8caaee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102"
    family = "Prometei"
    file_name = "dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102"
    file_type = "elf"
    first_seen = "2026-09-17 02:51:41"
  condition:
    hash.sha256(0, filesize) == "dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102"
}
```

### Sample 33: `9743f6525b96c60d`

| Field | Value |
|---|---|
| SHA-256 | `9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd` |
| Family label | `unknown` |
| File name | `9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd` |
| File type | `exe` |
| First seen | `2026-09-17 02:51:18` |
| Reporter | `c2hunter` |
| Tags | `exe, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `999379bede69c12db59ab71dd05b65f5` |
| SHA-1 | `946752a5f7d6582eac13a43abec76e3d4740b1c2` |
| SHA-256 | `9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd` |
| SHA3-384 | `980366a93ab8c46d39e92a2ac437833178145ff5834bb21a0f7373917bfd43329b120a5ace897ed1ba241cdb9a07305a` |
| IMPHASH | `899ad1596f9c6642245b3fb721bae585` |
| TLSH | `T10534BE63A4BCAA9FDDD82F379C4E880713B66FE4D890603E1C44710EFE2A5095F7A516` |
| SSDEEP | `6144:JGxCfPf0s3KPHfBxR8jPs1F1yD9jvryfL9SqXVdOY:JG60BpL8jk1FGjDc8GVdOY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_9743f652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd"
    family = "unknown"
    file_name = "9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd"
    file_type = "exe"
    first_seen = "2026-09-17 02:51:18"
  condition:
    hash.sha256(0, filesize) == "9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd"
}
```

### Sample 34: `ac4bab56a5cb00a8`

| Field | Value |
|---|---|
| SHA-256 | `ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833` |
| Family label | `unknown` |
| File name | `ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833.sh` |
| File type | `sh` |
| First seen | `2026-09-17 02:39:16` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7ffeed46b973582f0f8dd0abc78dad2` |
| SHA-1 | `0137b9fca5ff25ab4e9ba417a7b8ed5fcaa8b1b8` |
| SHA-256 | `ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833` |
| SHA3-384 | `5d2162368391687c078106ee63b813d7ccbc9a6aff00eb702a4b451137ca0f981c306c2bb79b91b3c54ad3eacd72ab5f` |
| TLSH | `T12F42673720F08B3297D061C962771A614FB2970B456714B8F4FE5B26AF2DA0370EBB61` |
| SSDEEP | `192:cCuR56p4hvZ5mN9oKNpivvV6PFITVaHvNMc8F:W0p4hvZ5mN9oKNpivvQPFITVaHvNMc8F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_ac4bab56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833"
    family = "unknown"
    file_name = "ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833.sh"
    file_type = "sh"
    first_seen = "2026-09-17 02:39:16"
  condition:
    hash.sha256(0, filesize) == "ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833"
}
```

### Sample 35: `b80a275eb2c3abe0`

| Field | Value |
|---|---|
| SHA-256 | `b80a275eb2c3abe0f0a497eac27c908628f3472f9a3de0e8f4d7518e4c965a2d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:23:22` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5218016ff8cf531506ab61cdae7cdcd1` |
| SHA-1 | `b49396fcdbbf0e8cf906710ab8e7e7ef3249931f` |
| SHA-256 | `b80a275eb2c3abe0f0a497eac27c908628f3472f9a3de0e8f4d7518e4c965a2d` |
| SHA3-384 | `09d6676b8a428dec575123b5030a263a3ce315f405a6b595492edfa22e4c01bbb9825588a73039f2767fa95b0c8615ec` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A462C786E9A21F7CCE4E80707A11F878BD7136958E6569F3DB828C359DA38D04024EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UC5Z6e:fKOe2/7c9sN3zfZR1m+RGXc6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_b80a275e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b80a275eb2c3abe0f0a497eac27c908628f3472f9a3de0e8f4d7518e4c965a2d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:23:22"
  condition:
    hash.sha256(0, filesize) == "b80a275eb2c3abe0f0a497eac27c908628f3472f9a3de0e8f4d7518e4c965a2d"
}
```

### Sample 36: `3d76d141c05ca1e5`

| Field | Value |
|---|---|
| SHA-256 | `3d76d141c05ca1e5f354e489c81b1266e844043fa4c50de0ce41560c3b960881` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:20:31` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23d0cc19df4ba565e34b0b3a79661987` |
| SHA-1 | `814ece304ac84cbaf2f219e8a39182f13b8a6565` |
| SHA-256 | `3d76d141c05ca1e5f354e489c81b1266e844043fa4c50de0ce41560c3b960881` |
| SHA3-384 | `eceec7c77618c6550e57868257d88e3fcf0a8142beb5a8c64b4856e2770889fed41b587fcc2f068983509961c4bc33de` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10A62D68ADDA26F5CDE8F80703A15F938AD7132A5866559E3D7828C305EA39D10134FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UuizBM:fKOe2/7c9sN3zfZR1m+RGziz6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_3d76d141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d76d141c05ca1e5f354e489c81b1266e844043fa4c50de0ce41560c3b960881"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:20:31"
  condition:
    hash.sha256(0, filesize) == "3d76d141c05ca1e5f354e489c81b1266e844043fa4c50de0ce41560c3b960881"
}
```

### Sample 37: `c05ab4efaa834070`

| Field | Value |
|---|---|
| SHA-256 | `c05ab4efaa83407081c78bd9c4da34ca5fd004e595add11b26e2905463d530c5` |
| Family label | `unknown` |
| File name | `PlatinumRSVP.msi` |
| File type | `msi` |
| First seen | `2026-09-17 02:19:53` |
| Reporter | `anonymous` |
| Tags | `msi, opsbridge` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bda52f0d79df40ad465f37b90560b93f` |
| SHA-256 | `c05ab4efaa83407081c78bd9c4da34ca5fd004e595add11b26e2905463d530c5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_c05ab4ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c05ab4efaa83407081c78bd9c4da34ca5fd004e595add11b26e2905463d530c5"
    family = "unknown"
    file_name = "PlatinumRSVP.msi"
    file_type = "msi"
    first_seen = "2026-09-17 02:19:53"
  condition:
    hash.sha256(0, filesize) == "c05ab4efaa83407081c78bd9c4da34ca5fd004e595add11b26e2905463d530c5"
}
```

### Sample 38: `26419c134a60de42`

| Field | Value |
|---|---|
| SHA-256 | `26419c134a60de42e1b72663b5e27623ea7237c3d160846104af440c39b35cbe` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:18:18` |
| Reporter | `Bitsight` |
| Tags | `368eb34be1e7e495c94952b194824099, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `539fcfb21edae7000e178e744761104a` |
| SHA-1 | `4621d5dde7bb6bb9b7862f0a55c6c90fe5d765b5` |
| SHA-256 | `26419c134a60de42e1b72663b5e27623ea7237c3d160846104af440c39b35cbe` |
| SHA3-384 | `bb330e9c2606b071f03322cd4600179337fe21e96199ec998dfe9a00351b30047d140f3b0a4bcd585c294640dfb3b78f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E962D58AD9A22E6DDE4E80703F11F878BDB47690866599E3D7928D305EA39D10024FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UPTmLN:fKOe2/7c9sN3zfZR1m+RGwThEM6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_26419c13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26419c134a60de42e1b72663b5e27623ea7237c3d160846104af440c39b35cbe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:18:18"
  condition:
    hash.sha256(0, filesize) == "26419c134a60de42e1b72663b5e27623ea7237c3d160846104af440c39b35cbe"
}
```

### Sample 39: `4f8c76660cb28a7b`

| Field | Value |
|---|---|
| SHA-256 | `4f8c76660cb28a7b8b59b4bdea358c9fd101b6a1999213049defec1fa69cef1c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:18:12` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `632b2c6fea992b872318a2997ec20104` |
| SHA-1 | `f231b28677329cd78f9e85ab206d958b1960fac4` |
| SHA-256 | `4f8c76660cb28a7b8b59b4bdea358c9fd101b6a1999213049defec1fa69cef1c` |
| SHA3-384 | `f997594eb4a1009d1d223546ab880cdfb03dc3037c41b42a92331b4bc3b693df66a85c570aecb044d4fb7eb54336945e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C562C78AD9A25F6DCE4F80703B12F8786D7576908A6599E7D7868C315EA3CC01034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UaqXze:fKOe2/7c9sN3zfZR1m+RG/0z6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_4f8c7666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f8c76660cb28a7b8b59b4bdea358c9fd101b6a1999213049defec1fa69cef1c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:18:12"
  condition:
    hash.sha256(0, filesize) == "4f8c76660cb28a7b8b59b4bdea358c9fd101b6a1999213049defec1fa69cef1c"
}
```

### Sample 40: `d9c70679d03602fc`

| Field | Value |
|---|---|
| SHA-256 | `d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991` |
| Family label | `unknown` |
| File name | `d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991` |
| File type | `elf` |
| First seen | `2026-09-17 02:17:25` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `447950e299a799b65d402b673895a9f5` |
| SHA-1 | `35352406ef101df314ba7ec869b8edc3c403def3` |
| SHA-256 | `d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991` |
| SHA3-384 | `d569975a601903b9bb6e8046ad416e13ea4de4ce31b815f93c0db773bb271d11cab964bafc1ba0b0aa09696037032bff` |
| TLSH | `T14AD3128AEF369C0ECF401EB22ADB5F8E9C6D796B41CBF4A4B9C1818F17A01C97D52115` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ10xd:p3lOYoaja8xzx/0wsxzSd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_d9c70679
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991"
    family = "unknown"
    file_name = "d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991"
    file_type = "elf"
    first_seen = "2026-09-17 02:17:25"
  condition:
    hash.sha256(0, filesize) == "d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991"
}
```

### Sample 41: `fc1db604acc536bc`

| Field | Value |
|---|---|
| SHA-256 | `fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88` |
| Family label | `unknown` |
| File name | `fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88` |
| File type | `elf` |
| First seen | `2026-09-17 02:17:19` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f4fd2fddb23e2001253aa8f7d9b4bce` |
| SHA-1 | `7df16477d19d468301c526b4710ed73a2e9911df` |
| SHA-256 | `fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88` |
| SHA3-384 | `cbfc8bc226013e85d1e1bbc88bb48c0a9cdf238c973867b4e092f583aab211423e0ca7e22637cd2933b6a8c4fb61f71a` |
| TLSH | `T121C3136293230C4BC42538FEBE16E6162D872E69288D409D46F5D67A5FB7088EAF1353` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lx9:biMYFJvw6Yh0b1gKobtCGCmCRlrisF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_fc1db604
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88"
    family = "unknown"
    file_name = "fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88"
    file_type = "elf"
    first_seen = "2026-09-17 02:17:19"
  condition:
    hash.sha256(0, filesize) == "fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88"
}
```

### Sample 42: `068e0c4c8a5d4a96`

| Field | Value |
|---|---|
| SHA-256 | `068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1` |
| Family label | `unknown` |
| File name | `068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1` |
| File type | `elf` |
| First seen | `2026-09-17 02:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72129870be4d26533b8b35936d00dff3` |
| SHA-1 | `04164f99000d8985300d0046de748c7357fdd1d4` |
| SHA-256 | `068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1` |
| SHA3-384 | `91322105359583662fcd7e1ce7714064383cd0bf14cad00507d2981457d31c13e1c2b9b83bedcb728c913020107a7c25` |
| TLSH | `T1FE24198AFC81AF5595C127BBFE2E418A331317B8E2EE71129D145F2477CA94F0E3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqQ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_068e0c4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1"
    family = "unknown"
    file_name = "068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1"
    file_type = "elf"
    first_seen = "2026-09-17 02:17:12"
  condition:
    hash.sha256(0, filesize) == "068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1"
}
```

### Sample 43: `354dbe764cc11cdb`

| Field | Value |
|---|---|
| SHA-256 | `354dbe764cc11cdbe73ab6439f00cd01e4ef70b1ab17dece1c853d28e89d600d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:15:57` |
| Reporter | `Bitsight` |
| Tags | `368eb34be1e7e495c94952b194824099, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcd6d8e4eed9c043b2e80657aaf9c80c` |
| SHA-1 | `1b17480cfc767e3243ddde32cbe1c1c8b7293018` |
| SHA-256 | `354dbe764cc11cdbe73ab6439f00cd01e4ef70b1ab17dece1c853d28e89d600d` |
| SHA3-384 | `4f2897dc76f457d1d666e4a8018f0780c0ff9938d135a40e7c2fe7c42d27e873d49b71da1c7305ab5a40abf40001e301` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B762D68AD8E21F5CDE4E80703B11F978BD7476D48665AAE7D7828C318DA39D00028FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U8qAAc:fKOe2/7c9sN3zfZR1m+RGZw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_354dbe76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "354dbe764cc11cdbe73ab6439f00cd01e4ef70b1ab17dece1c853d28e89d600d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:15:57"
  condition:
    hash.sha256(0, filesize) == "354dbe764cc11cdbe73ab6439f00cd01e4ef70b1ab17dece1c853d28e89d600d"
}
```

### Sample 44: `2dd4d23f5ebf2549`

| Field | Value |
|---|---|
| SHA-256 | `2dd4d23f5ebf25492f62fc9b2db0ec48c632825a6f2ff189b844b72f8c233a0e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:15:25` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0606182d3e5ba84ed89908e983fd0e94` |
| SHA-1 | `731bf67ba7f216ebb011e8909033bc15d98eb965` |
| SHA-256 | `2dd4d23f5ebf25492f62fc9b2db0ec48c632825a6f2ff189b844b72f8c233a0e` |
| SHA3-384 | `a2d4b79b5e764e182c8a05595d37df74cef206f18d356763b2b6ac17a24ac839756f04b046dca23f70b384c4cf0806d5` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14662B596D9A26F6DCE4F80703A11F838A9F9369096665DE3D782CC315DB39D00029EFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGeMMMMMMMMMMMMMMMMMMMMMMX76C:fKOeOQOzUxeMMMMMMMMMMMMMMMMMMMMe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_2dd4d23f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd4d23f5ebf25492f62fc9b2db0ec48c632825a6f2ff189b844b72f8c233a0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:15:25"
  condition:
    hash.sha256(0, filesize) == "2dd4d23f5ebf25492f62fc9b2db0ec48c632825a6f2ff189b844b72f8c233a0e"
}
```

### Sample 45: `b1c921e71f896bed`

| Field | Value |
|---|---|
| SHA-256 | `b1c921e71f896bed283a084b7a95d9b2d326aa8a902ad0e65e143caf897f2c5d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:13:00` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29a56018f3005f8a3857f28596b48bc6` |
| SHA-1 | `57a172a073c8ecedadd8183b6780ee0fdf48e1d5` |
| SHA-256 | `b1c921e71f896bed283a084b7a95d9b2d326aa8a902ad0e65e143caf897f2c5d` |
| SHA3-384 | `500899057804115445ebf0b73e0738c1a15d16f1d1a315680d56bad8bfe1ce94fb053f1d18c4af3135ae0acfd652b9d0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BA62C587E9D26EACCE4E80703E11F968BDB176A0D6655EE3D7C28C6059A38D00125EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uv5wie:fKOe2/7c9sN3zfZR1m+RGWL6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_b1c921e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1c921e71f896bed283a084b7a95d9b2d326aa8a902ad0e65e143caf897f2c5d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:13:00"
  condition:
    hash.sha256(0, filesize) == "b1c921e71f896bed283a084b7a95d9b2d326aa8a902ad0e65e143caf897f2c5d"
}
```

### Sample 46: `e98395e4f0c1b1a6`

| Field | Value |
|---|---|
| SHA-256 | `e98395e4f0c1b1a62ae5002f09c22d31d134f5bc6a3b1093d63df4fb9d89c2d2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 02:10:33` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `070e197a8d76c166aa8963d63792dd90` |
| SHA-1 | `20cae2d9b096fd2dfc28c9423710e438ac647ad8` |
| SHA-256 | `e98395e4f0c1b1a62ae5002f09c22d31d134f5bc6a3b1093d63df4fb9d89c2d2` |
| SHA3-384 | `d43d3eaf23a85a01489b83021493b21435abc264aab6589d3cc0e182c2d10e684e73271620754661720df961fb8d79e8` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18D62E786D9A26F5CCE8E80703E20F9BCAE7036A0852559F3DB828C345D639D14434FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U/tABM:fKOe2/7c9sN3zfZR1m+RGkm6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_e98395e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98395e4f0c1b1a62ae5002f09c22d31d134f5bc6a3b1093d63df4fb9d89c2d2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:10:33"
  condition:
    hash.sha256(0, filesize) == "e98395e4f0c1b1a62ae5002f09c22d31d134f5bc6a3b1093d63df4fb9d89c2d2"
}
```

### Sample 47: `3bd47c0e22be6dec`

| Field | Value |
|---|---|
| SHA-256 | `3bd47c0e22be6deca2d388cdfce57c3ee0ddfd7edcb2b950b11127c20ac63720` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-17 02:04:18` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf2a8dc6c93a8bcced5cc6b08b551397` |
| SHA-1 | `3c9c284fd93f11faf145715645b388d38bfc730a` |
| SHA-256 | `3bd47c0e22be6deca2d388cdfce57c3ee0ddfd7edcb2b950b11127c20ac63720` |
| SHA3-384 | `6d1f88e25435d225d5f9f5acfddd2cdef0d739d720362cfd18284269284d00ffeac3ea6783285f8252435af1e1d95109` |
| TLSH | `T15D137D6566813C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:YXRWNGxVH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:Mlxuco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_047_3bd47c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bd47c0e22be6deca2d388cdfce57c3ee0ddfd7edcb2b950b11127c20ac63720"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 02:04:18"
  condition:
    hash.sha256(0, filesize) == "3bd47c0e22be6deca2d388cdfce57c3ee0ddfd7edcb2b950b11127c20ac63720"
}
```

### Sample 48: `decd9cec9001b918`

| Field | Value |
|---|---|
| SHA-256 | `decd9cec9001b918b9cb930b3ed840e4446c61bd8e2279177ae090fd103818a6` |
| Family label | `GuLoader` |
| File name | `Skovtr.vbs` |
| File type | `vbs` |
| First seen | `2026-09-17 02:03:37` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67be538db5ef0106c2a6b7a1b6ae7f25` |
| SHA-1 | `693e277c3b326fd98c76345cbad03216c63910d4` |
| SHA-256 | `decd9cec9001b918b9cb930b3ed840e4446c61bd8e2279177ae090fd103818a6` |
| SHA3-384 | `f374efea3cecd8132413c08ca6c445df92f08929c4acccd14b35817c90743076ec80469e1550785675796d59d4e25d7d` |
| TLSH | `T1C4845B20ED3406694F471BA9FDA50B62CABD8609522650F5FEEE030D61065FCE3FE768` |
| SSDEEP | `6144:6XUtF7OVLKB+18CvlyuGcwYVjupFUpg+rdnNmg4i76SPSuUQpbq6QyM6TqyR:6X+clrGcwRmTbjr68` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_048_decd9cec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "decd9cec9001b918b9cb930b3ed840e4446c61bd8e2279177ae090fd103818a6"
    family = "GuLoader"
    file_name = "Skovtr.vbs"
    file_type = "vbs"
    first_seen = "2026-09-17 02:03:37"
  condition:
    hash.sha256(0, filesize) == "decd9cec9001b918b9cb930b3ed840e4446c61bd8e2279177ae090fd103818a6"
}
```

### Sample 49: `044f045e4eded22d`

| Field | Value |
|---|---|
| SHA-256 | `044f045e4eded22db7a1df66644133c9dedf2d408caa1fcaad2c4a36a3d9a6d2` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-17 01:59:33` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd8d52c9abe17aab4271758b12e99328` |
| SHA-1 | `2e745c0646e15e2f8eeaea369c1b1dc12307971d` |
| SHA-256 | `044f045e4eded22db7a1df66644133c9dedf2d408caa1fcaad2c4a36a3d9a6d2` |
| SHA3-384 | `857285e5411bee60a4648f5ac6d1e19514a3df403468a57179e64290f16fa1891e753c814d37062baa98b2e2b5640c00` |
| TLSH | `T14DC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:K8vCB+25j6es8R89FYpMSUpi+20qUpi+20YQX:K8l25JKd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_049_044f045e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044f045e4eded22db7a1df66644133c9dedf2d408caa1fcaad2c4a36a3d9a6d2"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-17 01:59:33"
  condition:
    hash.sha256(0, filesize) == "044f045e4eded22db7a1df66644133c9dedf2d408caa1fcaad2c4a36a3d9a6d2"
}
```

### Sample 50: `e5a560b673e6cda0`

| Field | Value |
|---|---|
| SHA-256 | `e5a560b673e6cda0c141f42b3b5e4e39eeedab62ecc97cd7f1f7d9f2ba3cdc60` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:51:12` |
| Reporter | `Bitsight` |
| Tags | `16660bde630116f363f759a4ac9d08fb, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2065dac7153aba26abc7aee70a393bba` |
| SHA-1 | `47704bdf6d7c488702055d39eb28b53274169573` |
| SHA-256 | `e5a560b673e6cda0c141f42b3b5e4e39eeedab62ecc97cd7f1f7d9f2ba3cdc60` |
| SHA3-384 | `5d1e28cd8e935d0964be7df636a8199e6f9688e11deda2084a2a8f4cf176a072c2a97654c19427b5ff843d769b0edd33` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EC62B586D8A26FACDE4E80703B11F868B97537D18AA55DE3D7928C315EA39D00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UnUhhD:fKOe2/7c9sN3zfZR1m+RGON6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_e5a560b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5a560b673e6cda0c141f42b3b5e4e39eeedab62ecc97cd7f1f7d9f2ba3cdc60"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:51:12"
  condition:
    hash.sha256(0, filesize) == "e5a560b673e6cda0c141f42b3b5e4e39eeedab62ecc97cd7f1f7d9f2ba3cdc60"
}
```

### Sample 51: `14e4ec273e801244`

| Field | Value |
|---|---|
| SHA-256 | `14e4ec273e801244be442486bee870b4598eb3c55c8455f73b46b6776e961945` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:48:50` |
| Reporter | `Bitsight` |
| Tags | `16660bde630116f363f759a4ac9d08fb, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84874c758ff77ca1f82d76b455ab435a` |
| SHA-1 | `bd86d864e154d7ba030fd0523004c81921782abb` |
| SHA-256 | `14e4ec273e801244be442486bee870b4598eb3c55c8455f73b46b6776e961945` |
| SHA3-384 | `72d16ae28a37d02e54936be9f0b21f6ad4e234c3fd30ce0773ae1a84910ea18820b85e7ac147f8b508ce73f9eb563919` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12562E796D8A22F6DDE4EC0703A11FC787D7536918A65A9EBE7828D309D638C01434EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46URZZ7C:fKOe2/7c9sN3zfZR1m+RGWZ7T6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_14e4ec27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14e4ec273e801244be442486bee870b4598eb3c55c8455f73b46b6776e961945"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:48:50"
  condition:
    hash.sha256(0, filesize) == "14e4ec273e801244be442486bee870b4598eb3c55c8455f73b46b6776e961945"
}
```

### Sample 52: `d4118662e8bf1205`

| Field | Value |
|---|---|
| SHA-256 | `d4118662e8bf1205dc79037da13b99cf4cc18544c5b2bb3227f51bc4bf8d2324` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:46:28` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `328575e873bc96c7c2d49d4c756351df` |
| SHA-1 | `3a476a16939d2ed05588e7c16271c4a25d03443b` |
| SHA-256 | `d4118662e8bf1205dc79037da13b99cf4cc18544c5b2bb3227f51bc4bf8d2324` |
| SHA3-384 | `b898a960fce3dc2d4198a679cfeab1204c301f35cef492fbebd396c10483ed09885043af8297cca7678f6aedb8864266` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16662D78AE8A16F5CDF4E90703E21F83C7972329485669AE7D7828C715E639D00474EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UpOOOX:fKOe2/7c9sN3zfZR1m+RGK6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_d4118662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4118662e8bf1205dc79037da13b99cf4cc18544c5b2bb3227f51bc4bf8d2324"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:46:28"
  condition:
    hash.sha256(0, filesize) == "d4118662e8bf1205dc79037da13b99cf4cc18544c5b2bb3227f51bc4bf8d2324"
}
```

### Sample 53: `3ea5c705b933852d`

| Field | Value |
|---|---|
| SHA-256 | `3ea5c705b933852d96c1ad160739dfeb2b614d526d684fc1b83a64f067bd9d7b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:41:52` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7591a1bad4d059e1a45c0a50a8351ce` |
| SHA-1 | `d4f87a010aaf55cafcfe1f0f08ec7e38e3cae8ec` |
| SHA-256 | `3ea5c705b933852d96c1ad160739dfeb2b614d526d684fc1b83a64f067bd9d7b` |
| SHA3-384 | `afd7542bd9953d1852f3c752aee21c7e514f6614dcf4fd2eb8e3ed2547ec4ed88ce1fa1c7cc634eadb2062ef6abd7295` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16A62C786D9A22F5DCF4E90B03A11F83C79B936908A6559E3D7828C305DA39D04538EFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UIzqBM:fKOe2/7c9sN3zfZR1m+RGdzq6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_3ea5c705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ea5c705b933852d96c1ad160739dfeb2b614d526d684fc1b83a64f067bd9d7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:41:52"
  condition:
    hash.sha256(0, filesize) == "3ea5c705b933852d96c1ad160739dfeb2b614d526d684fc1b83a64f067bd9d7b"
}
```

### Sample 54: `fba460aa8917b70a`

| Field | Value |
|---|---|
| SHA-256 | `fba460aa8917b70a79affe248e7f2287672d562c9d2815948641835a7f461f2c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:37:10` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f245cc8d1fb830ef115d508d81a0243a` |
| SHA-1 | `8880ca0f623cccea4205e5c04beb3ab8aa752d87` |
| SHA-256 | `fba460aa8917b70a79affe248e7f2287672d562c9d2815948641835a7f461f2c` |
| SHA3-384 | `b1c11955a8fd0e3584a2fe7f456a56bcb93ea784fd76745eed562352782d83a2ccaeaf4bc8058936d142e25f1e00fe7d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F662F68AD8A21F5DCE4F90703A21FA78BD7072948A2599E3C7928D315DB79D04434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJBjle:fKOe2/7c9sN3zfZR1m+RG8Bjl6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_fba460aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba460aa8917b70a79affe248e7f2287672d562c9d2815948641835a7f461f2c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:37:10"
  condition:
    hash.sha256(0, filesize) == "fba460aa8917b70a79affe248e7f2287672d562c9d2815948641835a7f461f2c"
}
```

### Sample 55: `74818afc20636033`

| Field | Value |
|---|---|
| SHA-256 | `74818afc20636033da8b02151d8226e6cc5dcc085a47e7416341120c79ac8ef7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:36:29` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65334c1360043a880ba9dab4d0d91c34` |
| SHA-1 | `92ddc5966d6724a04a146478f8d41b90d306799a` |
| SHA-256 | `74818afc20636033da8b02151d8226e6cc5dcc085a47e7416341120c79ac8ef7` |
| SHA3-384 | `f0aed2600e5c53aa74430f8cd6975db6e4ff0d8b6727d0e0b2d9b8b55ec886baa914f51bfcf07056221852e71bf6075e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10B62D686D9A32F5DCE4E80703A21F838A9B436D08A6569E7DB928C705DB79D00524FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uillls:fKOe2/7c9sN3zfZR1m+RGX6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_74818afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74818afc20636033da8b02151d8226e6cc5dcc085a47e7416341120c79ac8ef7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:36:29"
  condition:
    hash.sha256(0, filesize) == "74818afc20636033da8b02151d8226e6cc5dcc085a47e7416341120c79ac8ef7"
}
```

### Sample 56: `6e87682bbd1ec48d`

| Field | Value |
|---|---|
| SHA-256 | `6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb` |
| Family label | `unknown` |
| File name | `6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb` |
| File type | `elf` |
| First seen | `2026-09-17 01:35:25` |
| Reporter | `beserko` |
| Tags | `diicot, elf, mexals, miner, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b56d10a32921866e5db21c52d54e29de` |
| SHA-1 | `159d6d1a7b47397d455be29029d1e1402b423c43` |
| SHA-256 | `6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb` |
| SHA3-384 | `e18f59a084036376487709cb716f857e99d32ef1fd43cd334ac772c1611a99005661919b57fde745ad44dbf6eed6299e` |
| TLSH | `T1F2656C1BB59250FDC1D7C070839B9633AA32B49952347E7F62C4AF312E26F20675EB61` |
| SSDEEP | `24576:MOWkFlK+FsHoFSMdVnFmyJJd0qO/49CIIe2unlsIbviiEtH438ZEKUUkXTW+aN:MOpFRF8oFPvnl50p+0eVlvviccN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_6e87682b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb"
    family = "unknown"
    file_name = "6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb"
    file_type = "elf"
    first_seen = "2026-09-17 01:35:25"
  condition:
    hash.sha256(0, filesize) == "6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb"
}
```

### Sample 57: `c4212a5c75d9af22`

| Field | Value |
|---|---|
| SHA-256 | `c4212a5c75d9af22cfa1cacdf7ef46172d9808ad12978e9fb9fbeff7d591e3e1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:34:46` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7d7dbb2c9b7654e10bbba662e1e04fa` |
| SHA-1 | `18829ed168443b1029a40a9f0779028095870d16` |
| SHA-256 | `c4212a5c75d9af22cfa1cacdf7ef46172d9808ad12978e9fb9fbeff7d591e3e1` |
| SHA3-384 | `c1c1b4ee594e63883797c4cad22964c3db16982cc3e02916ca0727f8d17b990c8084e20f20920416a95a952635edac56` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D962C79AD8E22F6CDE4FD0703A11F9786A7036A1866599F3EF928C3459738D00035EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U7HBgn:fKOe2/7c9sN3zfZR1m+RGs6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_c4212a5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4212a5c75d9af22cfa1cacdf7ef46172d9808ad12978e9fb9fbeff7d591e3e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:34:46"
  condition:
    hash.sha256(0, filesize) == "c4212a5c75d9af22cfa1cacdf7ef46172d9808ad12978e9fb9fbeff7d591e3e1"
}
```

### Sample 58: `b595b2a6e6884fab`

| Field | Value |
|---|---|
| SHA-256 | `b595b2a6e6884fabc556a84f0cb75fe8625aa685dc11f8de3f905fac0cdb8c90` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:34:00` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a8f63286ad2ccc75e35847506b64a7f` |
| SHA-1 | `6a1d42294d760650a51f61281c8cc47e2c7c0732` |
| SHA-256 | `b595b2a6e6884fabc556a84f0cb75fe8625aa685dc11f8de3f905fac0cdb8c90` |
| SHA3-384 | `8e8a7513e5d793e3bf6c0ff23f3fa107813adddbb4bfe602ca19c67d8f493031be57bf4b6c5c0342342bac485b09ff85` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19C62D6CAF9926E5CDE8FD0703A11F8387E743290866569E3D7928D215DB38D00568FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ul2eBM:fKOe2/7c9sN3zfZR1m+RGze6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_b595b2a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b595b2a6e6884fabc556a84f0cb75fe8625aa685dc11f8de3f905fac0cdb8c90"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:34:00"
  condition:
    hash.sha256(0, filesize) == "b595b2a6e6884fabc556a84f0cb75fe8625aa685dc11f8de3f905fac0cdb8c90"
}
```

### Sample 59: `afa9fcf6e7524c6c`

| Field | Value |
|---|---|
| SHA-256 | `afa9fcf6e7524c6c03aaeea0ee1878617088368956c0612f4091590b43f4c196` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-17 01:33:33` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdd8ad0bbe1f03366591ebac643c522f` |
| SHA-1 | `6c0f69d486ef03ffad7e9de56947046f2b9fa2cd` |
| SHA-256 | `afa9fcf6e7524c6c03aaeea0ee1878617088368956c0612f4091590b43f4c196` |
| SHA3-384 | `20ea950abc5a2fa6c61f4a886362c6709d55814ca9cb929953bca8822deb2bbf5f3b139f1bea7e8777399e1d1d6af5df` |
| TLSH | `T1DA136D6516953C25AE99883B5C7F2F0CBDA983E1304491DDBF8A3CF18C15A9CE318719` |
| SSDEEP | `768:cr9NyXsZztC69GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:6HusZCco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_059_afa9fcf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afa9fcf6e7524c6c03aaeea0ee1878617088368956c0612f4091590b43f4c196"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 01:33:33"
  condition:
    hash.sha256(0, filesize) == "afa9fcf6e7524c6c03aaeea0ee1878617088368956c0612f4091590b43f4c196"
}
```

### Sample 60: `e3a0147b49398d98`

| Field | Value |
|---|---|
| SHA-256 | `e3a0147b49398d983c8d65a9c619bd7e4c30ad58109323efcf2db6e9d401e9cd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:32:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fb1e0fa93a2213c9641bd9c2d0ac753` |
| SHA-1 | `c8a53581301871ae3f5971ce926a02f92a2ca037` |
| SHA-256 | `e3a0147b49398d983c8d65a9c619bd7e4c30ad58109323efcf2db6e9d401e9cd` |
| SHA3-384 | `99aa6a2a043978eed9076507bb04dd2b159fd079d888f70f9ecd2691ce19e8d543be253d8d1df88aeffe93f5a76c4ce4` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14062C58AD9A26E5CDE4E80B03E11FC78BD713690896569F3D7C28C619DA39D00464FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UGT/Xu:fKOe2/7c9sN3zfZR1m+RGR/n6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_e3a0147b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3a0147b49398d983c8d65a9c619bd7e4c30ad58109323efcf2db6e9d401e9cd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:32:27"
  condition:
    hash.sha256(0, filesize) == "e3a0147b49398d983c8d65a9c619bd7e4c30ad58109323efcf2db6e9d401e9cd"
}
```

### Sample 61: `df540e050ac8f07b`

| Field | Value |
|---|---|
| SHA-256 | `df540e050ac8f07b503203500b12839c7a9a0b0ef6dfc0c4d9ea62fcd4ce8ca9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:31:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94e08adeeb5cf9debfc8393faa3a283f` |
| SHA-1 | `3ab9c7c0887ff11e1dec77035eae973b741be25c` |
| SHA-256 | `df540e050ac8f07b503203500b12839c7a9a0b0ef6dfc0c4d9ea62fcd4ce8ca9` |
| SHA3-384 | `c0835b92b6bed6eeb18d6b96d98d90452b239bc38c0dad634a84d14ae2e0b3871f8f1222d5aa75f876ed71fc9309e21f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EC62B58AD8D26E6CDE4E80703A12F868BE7576E48A655DF7D7828C2459A39D00034FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UgISBM:fKOe2/7c9sN3zfZR1m+RGhIS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_df540e05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df540e050ac8f07b503203500b12839c7a9a0b0ef6dfc0c4d9ea62fcd4ce8ca9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:31:36"
  condition:
    hash.sha256(0, filesize) == "df540e050ac8f07b503203500b12839c7a9a0b0ef6dfc0c4d9ea62fcd4ce8ca9"
}
```

### Sample 62: `9b5d20de3bc902c4`

| Field | Value |
|---|---|
| SHA-256 | `9b5d20de3bc902c481465ec98d4ffd5c6656ea395a47858b31a320fb2675e754` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 01:25:24` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2ddde96a640e5e98248a5eecd553eed` |
| SHA-1 | `a31113acc056c90b5a2c22ff128e69b15c1eeb28` |
| SHA-256 | `9b5d20de3bc902c481465ec98d4ffd5c6656ea395a47858b31a320fb2675e754` |
| SHA3-384 | `c1e31bb65f6650ec19f64cc3ebc16847d36e2ac6fc105878825a21afe0819ad31e6dffc2ffdc4611eb2f74d3d3f8a1dc` |
| IMPHASH | `351fa95d57f1cb1393ecf033d61ebeaf` |
| TLSH | `T138E4F0166E5B23F8EC7CA378C496BE19F636B01B8301678F17B003552E367E51E1BA16` |
| SSDEEP | `12288:xmGjQJGdqiFCgWJUMpsWIbiYY03tScl5Ad24WVuuaRwk:xcyxRWIb4sSK5I24WAuaRw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_9b5d20de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b5d20de3bc902c481465ec98d4ffd5c6656ea395a47858b31a320fb2675e754"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:25:24"
  condition:
    hash.sha256(0, filesize) == "9b5d20de3bc902c481465ec98d4ffd5c6656ea395a47858b31a320fb2675e754"
}
```

### Sample 63: `5f3812aa9b0d7bd2`

| Field | Value |
|---|---|
| SHA-256 | `5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412` |
| Family label | `unknown` |
| File name | `5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412` |
| File type | `elf` |
| First seen | `2026-09-17 01:17:26` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84706d7387887631b8fb5dd84c3aebd1` |
| SHA-1 | `38b33c228fbeda55874cd306785b723d754e3009` |
| SHA-256 | `5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412` |
| SHA3-384 | `39f81ea050d31e248bceb84b583a05f36e7c7af7f8fbe14106e8f4bd585bb71b46579303ca88dd000a6e298b448be2d6` |
| TLSH | `T10DB3124EEF319C1B9F4019B32ADA5E8EDC697B6B01CBB4A869C2D14F47A10CD7C52218` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+Vc:phNlHuBafLeBtfCzpta8xlBIOdVo3//` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_5f3812aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412"
    family = "unknown"
    file_name = "5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412"
    file_type = "elf"
    first_seen = "2026-09-17 01:17:26"
  condition:
    hash.sha256(0, filesize) == "5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412"
}
```

### Sample 64: `d97bb4393a46028f`

| Field | Value |
|---|---|
| SHA-256 | `d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522` |
| Family label | `Mozi` |
| File name | `d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522` |
| File type | `elf` |
| First seen | `2026-09-17 01:17:20` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips, Mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `065d33b98023509b88dbc48b2aed1bc7` |
| SHA-1 | `5b17b5c8cf3b641ddb08bf622522a21d27e6ac17` |
| SHA-256 | `d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522` |
| SHA3-384 | `e62044a960ba8b9caafab8d0378ed50fe5ac1ea7b41b2d646c4600f8b09ab73e842bdf40eab01ae28e2059ba5e2feba0` |
| TLSH | `T1D7C3125193220D0BC42538FABE26E6162D862E79248E409C46F5E67B5FB70DCEAF1353` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxj:biMYFJvw6Yh0b1gKobtCGCmCRlrd` |

#### Technical Assessment

- The sample is tracked as `Mozi` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mozi_064_d97bb439
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522"
    family = "Mozi"
    file_name = "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522"
    file_type = "elf"
    first_seen = "2026-09-17 01:17:20"
  condition:
    hash.sha256(0, filesize) == "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522"
}
```

### Sample 65: `ae2c632f0a5a54e1`

| Field | Value |
|---|---|
| SHA-256 | `ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104` |
| Family label | `Mirai` |
| File name | `ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104` |
| File type | `elf` |
| First seen | `2026-09-17 01:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af31cbaf085dd97bd6b5bb2f739fd68c` |
| SHA-1 | `e776f67018b29db0080a398d16122a4589a8eebd` |
| SHA-256 | `ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104` |
| SHA3-384 | `6516846f2451371ba87559ec7f009fbe3aea8a6e48a8b88466e89f866ccff420405abd5edb0d5fe03f85d1740cadc472` |
| TLSH | `T1BB041A8AFD81AF1585D527BBFE2E418A331317B8D2EE71129D141F2877CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSDPb:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_ae2c632f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104"
    family = "Mirai"
    file_name = "ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104"
    file_type = "elf"
    first_seen = "2026-09-17 01:17:13"
  condition:
    hash.sha256(0, filesize) == "ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104"
}
```

### Sample 66: `a7af6e228b27fb60`

| Field | Value |
|---|---|
| SHA-256 | `a7af6e228b27fb60dd2287c220f06b9a092ba2fc64d0bcafa65fbbc3a47e5a6d` |
| Family label | `unknown` |
| File name | `update.mips` |
| File type | `elf` |
| First seen | `2026-09-17 01:16:56` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1324754a162b41614a43767bfac56747` |
| SHA-1 | `4731ad061ca07d8c035254fd47b55c44fef172e1` |
| SHA-256 | `a7af6e228b27fb60dd2287c220f06b9a092ba2fc64d0bcafa65fbbc3a47e5a6d` |
| SHA3-384 | `7480b93361b5aa6733bf80f139dd6346263ce0c468bbaf57917f674725dedf677ed1c46bd369c6d621ebe2541c724cd9` |
| TLSH | `T1B6411CEDB7D59773C089BFB252F212485072423AD8064AB9CE4B36F7145FC2E04B161B` |
| SSDEEP | `48:kz2g03aZEOcch8mwoWQbuBrWq9seDLbgiFqEdOfiEkINjyHaGA:Z+woWdAeDLbkfD17GA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_a7af6e22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7af6e228b27fb60dd2287c220f06b9a092ba2fc64d0bcafa65fbbc3a47e5a6d"
    family = "unknown"
    file_name = "update.mips"
    file_type = "elf"
    first_seen = "2026-09-17 01:16:56"
  condition:
    hash.sha256(0, filesize) == "a7af6e228b27fb60dd2287c220f06b9a092ba2fc64d0bcafa65fbbc3a47e5a6d"
}
```

### Sample 67: `e012af052ab3266d`

| Field | Value |
|---|---|
| SHA-256 | `e012af052ab3266d353194bf035e49f94523ca34f05ce7b2f13cffcae684f7fd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:36:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `961b183784cab74708cb32f932eed7a0` |
| SHA-1 | `f5775240a2de22f6b9da01175074bf838fd1e2b3` |
| SHA-256 | `e012af052ab3266d353194bf035e49f94523ca34f05ce7b2f13cffcae684f7fd` |
| SHA3-384 | `0a34fbe47d155f32fb6f88c6699eadd59590b306cd7ba34ddeaffae21df5be37538201ebf569bed24ddc90c721f51d74` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C462B5C6E8922FDCDE4E90B07F11F868B97476E0966569F3D7828C215AA39D00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UNdBgn:fKOe2/7c9sN3zfZR1m+RGw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_e012af05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e012af052ab3266d353194bf035e49f94523ca34f05ce7b2f13cffcae684f7fd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:36:19"
  condition:
    hash.sha256(0, filesize) == "e012af052ab3266d353194bf035e49f94523ca34f05ce7b2f13cffcae684f7fd"
}
```

### Sample 68: `f5c0a557a1cd39be`

| Field | Value |
|---|---|
| SHA-256 | `f5c0a557a1cd39beabca33ce63485d285f1180ef8d9e6dfcad5b65e5ff9c844c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:33:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b42fc3beff631c5c0b23918f36d84d80` |
| SHA-1 | `b8c8e5c436385fbbf3b4b2adefb674e04a302abc` |
| SHA-256 | `f5c0a557a1cd39beabca33ce63485d285f1180ef8d9e6dfcad5b65e5ff9c844c` |
| SHA3-384 | `8d41c3cea1f201bb183f683819c2b21710843b9f75fb49a3567e79e04316940bd89b68de35b876f128671222d9c2d123` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11062E686D8E22EACCE4E90703E11FC787DB476A5866959E7D7828C315DAB9C00434FF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RG0VmG5IIIIIIIIIy6C:fKOeOQOzUxUIIIIIIIIIy6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_f5c0a557
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c0a557a1cd39beabca33ce63485d285f1180ef8d9e6dfcad5b65e5ff9c844c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:33:49"
  condition:
    hash.sha256(0, filesize) == "f5c0a557a1cd39beabca33ce63485d285f1180ef8d9e6dfcad5b65e5ff9c844c"
}
```

### Sample 69: `31bc6b0c74347b3b`

| Field | Value |
|---|---|
| SHA-256 | `31bc6b0c74347b3bd5446b52b4b1792d4f6c172fe100f87701b9deadf0bdaddb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:32:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6a29096da8bc87a0dd3f55f6c4a38b4` |
| SHA-1 | `7e43f0ec6ab7107633876e1d5507ecaf5f01324e` |
| SHA-256 | `31bc6b0c74347b3bd5446b52b4b1792d4f6c172fe100f87701b9deadf0bdaddb` |
| SHA3-384 | `7063578ba7e0a46484f5a1aea2063978bed359a87400311d438cbdc0acb8dfdabe1fa4a0504e9938aea86410cf0237bd` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BC62D696D8E22E5DCE8F90703B15F828B97036D18A2A59F7CB828D315DA38D10534EF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RG3sssssssssND6C:fKOeOQOzUx3sssssssssND6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_31bc6b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31bc6b0c74347b3bd5446b52b4b1792d4f6c172fe100f87701b9deadf0bdaddb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:32:39"
  condition:
    hash.sha256(0, filesize) == "31bc6b0c74347b3bd5446b52b4b1792d4f6c172fe100f87701b9deadf0bdaddb"
}
```

### Sample 70: `fe90a471cc5f82f8`

| Field | Value |
|---|---|
| SHA-256 | `fe90a471cc5f82f86c5258602c77a7867a84c95afe788a50e57c5b8362991ab5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:31:47` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96399bc690acf3beb5812daabb4b8e7a` |
| SHA-1 | `6ddaaa81b5ed11fd52373d4ab37479c18448d4bb` |
| SHA-256 | `fe90a471cc5f82f86c5258602c77a7867a84c95afe788a50e57c5b8362991ab5` |
| SHA3-384 | `4bb7dba939221e056568e47a8debdd0226caf976894402d170fd4ac7eca92963a22709122b4165d1463c60c7bed6088b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14262D68AD8921F5CDE4E81707B10FA78BE7132D1966A59E3D7828C315EA39D10034EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UXBgCc:fKOe2/7c9sN3zfZR1m+RGA6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_fe90a471
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe90a471cc5f82f86c5258602c77a7867a84c95afe788a50e57c5b8362991ab5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:31:47"
  condition:
    hash.sha256(0, filesize) == "fe90a471cc5f82f86c5258602c77a7867a84c95afe788a50e57c5b8362991ab5"
}
```

### Sample 71: `e744b8e3d2df35b6`

| Field | Value |
|---|---|
| SHA-256 | `e744b8e3d2df35b6c93078a93d6ee17f352ce1411975628191fae7627dfdd239` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:31:23` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f1dc6afb1bc8162eba5a2f49242ecef` |
| SHA-1 | `1deda8ead16888683f9fe8400fecceec5b0df968` |
| SHA-256 | `e744b8e3d2df35b6c93078a93d6ee17f352ce1411975628191fae7627dfdd239` |
| SHA3-384 | `2c7eedaf01d86f2053be8ff0d5ba60a09b810c1b296fc9c4a75b627ca28e3fcb26d2ad1710aeb4d404373c0a928251eb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16662C786E8922F5CDE4E80703A11F938BA75779496655DE3E7C28C345DB39C04424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46USABgn:fKOe2/7c9sN3zfZR1m+RGE6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_e744b8e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e744b8e3d2df35b6c93078a93d6ee17f352ce1411975628191fae7627dfdd239"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:31:23"
  condition:
    hash.sha256(0, filesize) == "e744b8e3d2df35b6c93078a93d6ee17f352ce1411975628191fae7627dfdd239"
}
```

### Sample 72: `1bd50b8202892d4d`

| Field | Value |
|---|---|
| SHA-256 | `1bd50b8202892d4dd885d18ba2e4eac4801a3eeef40d1c2b9915b7b109699e94` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:28:58` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc3900f01cb705eee29d3677289c052f` |
| SHA-1 | `c9e58d9904d8eb74f2098c00cd5c8f639e2d1ac2` |
| SHA-256 | `1bd50b8202892d4dd885d18ba2e4eac4801a3eeef40d1c2b9915b7b109699e94` |
| SHA3-384 | `b73f8e931496a015f4ec6b44f55dcf9070a073a07946dcf438b8802f3af9bebb87c84140d5aae048c8cdcc31fc3a925f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BE62B786E8E26B6DDF4E80703A21F8786DB43BD0466A99E3D7828C244D679D11064FFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGf9pZPPPPPPPPPP6C:fKOeOQOzUxf9jPPPPPPPPPP6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_1bd50b82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd50b8202892d4dd885d18ba2e4eac4801a3eeef40d1c2b9915b7b109699e94"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:28:58"
  condition:
    hash.sha256(0, filesize) == "1bd50b8202892d4dd885d18ba2e4eac4801a3eeef40d1c2b9915b7b109699e94"
}
```

### Sample 73: `eae16274ff967c4a`

| Field | Value |
|---|---|
| SHA-256 | `eae16274ff967c4a27449dc663b2183bb5d447fbe2078ff0db0bc9dafdeb7bc0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:20:46` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `127f2e25b812bbb1c448df34216690dc` |
| SHA-1 | `f2bc73c4b113f4114b8d65bc41945e04256b4033` |
| SHA-256 | `eae16274ff967c4a27449dc663b2183bb5d447fbe2078ff0db0bc9dafdeb7bc0` |
| SHA3-384 | `5b18e2139401ab48961e95efdb24279d00144d1c830389079c2b9410d96939e3b5342c02df360b3bb882e88a73454270` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13A62E786EDA21E5CDE4E90703A52FC686DB436A4862698F7D7D28C345DA38C04128FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UiqUBM:fKOe2/7c9sN3zfZR1m+RG36C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_eae16274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae16274ff967c4a27449dc663b2183bb5d447fbe2078ff0db0bc9dafdeb7bc0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:20:46"
  condition:
    hash.sha256(0, filesize) == "eae16274ff967c4a27449dc663b2183bb5d447fbe2078ff0db0bc9dafdeb7bc0"
}
```

### Sample 74: `0b8038d60d3fd332`

| Field | Value |
|---|---|
| SHA-256 | `0b8038d60d3fd332fb04b310637a2035a6807ddb522a1ebfb19f238297285760` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:18:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `128e44a00b377790578b0290a11e4a80` |
| SHA-1 | `9ccb30ed591230134d9f6cdbe612219f78d570ab` |
| SHA-256 | `0b8038d60d3fd332fb04b310637a2035a6807ddb522a1ebfb19f238297285760` |
| SHA3-384 | `34483e3f56ae6c01c553ed7117af2fb04bbb5cb202acf94b6cc512621fbc6eb61511fbfb91a512d3bd6c0881d39ca974` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18462B686D8D26E6CDE4E90703A11F878BE7036A087659AF3D7D28C245EA79D00124FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U6rnBM:fKOe2/7c9sN3zfZR1m+RG1rn6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_0b8038d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8038d60d3fd332fb04b310637a2035a6807ddb522a1ebfb19f238297285760"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:18:19"
  condition:
    hash.sha256(0, filesize) == "0b8038d60d3fd332fb04b310637a2035a6807ddb522a1ebfb19f238297285760"
}
```

### Sample 75: `62c39f280b1dacac`

| Field | Value |
|---|---|
| SHA-256 | `62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01` |
| Family label | `unknown` |
| File name | `62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01` |
| File type | `elf` |
| First seen | `2026-09-17 00:17:26` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64115723466741d1c74b2d4d48f32fa9` |
| SHA-1 | `5c0036ae559fc565ad9a16aa4617c375189eb140` |
| SHA-256 | `62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01` |
| SHA3-384 | `f273077a0f2830473e90dfded77a62f993d68f8d7299c822485cef3658a7134d20292b52806597234651e5385f46ed35` |
| TLSH | `T1E0B3124AFE359C0BDF4019B31ADE4F8ECC697B6B01CBB4A869C2944F57A01CD7D62218` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+Vz:phNlHuBafLeBtfCzpta8xlBIOdVo34` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_62c39f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01"
    family = "unknown"
    file_name = "62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01"
    file_type = "elf"
    first_seen = "2026-09-17 00:17:26"
  condition:
    hash.sha256(0, filesize) == "62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01"
}
```

### Sample 76: `cb53ff3b92cbda05`

| Field | Value |
|---|---|
| SHA-256 | `cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90` |
| Family label | `unknown` |
| File name | `cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90` |
| File type | `elf` |
| First seen | `2026-09-17 00:17:19` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `002036b9637783bec2e71360cf9adeab` |
| SHA-1 | `495bafd8dd3ef60e5def9d2cf48746987f930dd4` |
| SHA-256 | `cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90` |
| SHA3-384 | `713a2158ed2a9db2d1415516ac64bbb2c4fdd20008e787bb0abee8824e12cf2e0b8288f540a1764280227f10a4d560c5` |
| TLSH | `T108B30251D3230D0F843538FABA26E6152D872E79248A415D4AF5E67B4BB708CE9F6313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxh:biMYFJvw6Yh0b1gKobtCGCmCRlr7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_cb53ff3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90"
    family = "unknown"
    file_name = "cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90"
    file_type = "elf"
    first_seen = "2026-09-17 00:17:19"
  condition:
    hash.sha256(0, filesize) == "cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90"
}
```

### Sample 77: `2c8224b2f10417f3`

| Field | Value |
|---|---|
| SHA-256 | `2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd` |
| Family label | `Mirai` |
| File name | `2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd` |
| File type | `elf` |
| First seen | `2026-09-17 00:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d50b9910e384a234f0e00088138aec9` |
| SHA-1 | `587becaf07d434f2c220c4cc41c580b2c688df87` |
| SHA-256 | `2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd` |
| SHA3-384 | `628c89f32723c32c4e4f90f7b1099fcb83440d7af3774532b3b83efe6e6cee8013831eb42cfd759befa2dc076bd73b26` |
| TLSH | `T100C3088BBC91EE694AC0177BFE2E418E331327B4D1DF71139D141F58B68A94F0E6A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuau:T2s/gAWuboqsJ9xcJxspJBqQgTuau` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_2c8224b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd"
    family = "Mirai"
    file_name = "2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd"
    file_type = "elf"
    first_seen = "2026-09-17 00:17:13"
  condition:
    hash.sha256(0, filesize) == "2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd"
}
```

### Sample 78: `7934d8f55fd5d8f6`

| Field | Value |
|---|---|
| SHA-256 | `7934d8f55fd5d8f689a4568c3050246149dae29e1ceca7bc31dedcfdbdb96b3c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-17 00:15:45` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0909545f93af679f470df3483c9354dc` |
| SHA-1 | `91a3bd61bb1a41e8bc6d471a40f405d51de633d2` |
| SHA-256 | `7934d8f55fd5d8f689a4568c3050246149dae29e1ceca7bc31dedcfdbdb96b3c` |
| SHA3-384 | `cba62910da3eaed2e3a4385585cc9b6b1f7de7bd63c43b2ab31766c63702e2ffa2b294be099241a8e92921df07696ac5` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BB62C686D8E26F5CDE8E80703B11F938BDB4369486655AE3DB828C355DA39E10424FF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RG366Ew777777777kH6C:fKOeOQOzUx366t777777777kH6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_7934d8f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7934d8f55fd5d8f689a4568c3050246149dae29e1ceca7bc31dedcfdbdb96b3c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:15:45"
  condition:
    hash.sha256(0, filesize) == "7934d8f55fd5d8f689a4568c3050246149dae29e1ceca7bc31dedcfdbdb96b3c"
}
```

### Sample 79: `7070c769cd06c995`

| Field | Value |
|---|---|
| SHA-256 | `7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045` |
| Family label | `unknown` |
| File name | `7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045.bin` |
| File type | `unknown` |
| First seen | `2026-09-17 00:06:44` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa801f74f0622d80a866ca7561619939` |
| SHA-256 | `7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_7070c769
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045"
    family = "unknown"
    file_name = "7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045.bin"
    file_type = "unknown"
    first_seen = "2026-09-17 00:06:44"
  condition:
    hash.sha256(0, filesize) == "7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045"
}
```

### Sample 80: `016375769c3c8028`

| Field | Value |
|---|---|
| SHA-256 | `016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2` |
| Family label | `unknown` |
| File name | `016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2.bin` |
| File type | `unknown` |
| First seen | `2026-09-17 00:06:27` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d8f51e11e0ba03a87ad5e4ae9abc933` |
| SHA-256 | `016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_01637576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2"
    family = "unknown"
    file_name = "016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2.bin"
    file_type = "unknown"
    first_seen = "2026-09-17 00:06:27"
  condition:
    hash.sha256(0, filesize) == "016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2"
}
```

### Sample 81: `88cd0f5f6f0ed078`

| Field | Value |
|---|---|
| SHA-256 | `88cd0f5f6f0ed0780b450cc53f18136cb3f8245aef432e563ca30b6ec30bbfc6` |
| Family label | `unknown` |
| File name | `python312-runtime-apphost.zip` |
| File type | `zip` |
| First seen | `2026-09-17 00:03:04` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, SilentNet, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e9d03120fbf22907879c9328a07f6da` |
| SHA-1 | `d9a5c124433a06c79a05395ef3da3ddd3c7c730b` |
| SHA-256 | `88cd0f5f6f0ed0780b450cc53f18136cb3f8245aef432e563ca30b6ec30bbfc6` |
| SHA3-384 | `21632c4dd009397152b3e82021c6090c744636e68f36e323c30a3dbfb9089ba964d92a8266ca3332becfc4ef9ed4529e` |
| TLSH | `T132F63333C85653B7DADB9D321EF66D2B050EE16A7A1799DBBFA026503C331DA0127C09` |
| SSDEEP | `393216:PXMCHWUjetodaI8pEB1bSEKhmR44t0Mc933zqv80:PXMb8etDIDhKhmh+N933zCZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_88cd0f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88cd0f5f6f0ed0780b450cc53f18136cb3f8245aef432e563ca30b6ec30bbfc6"
    family = "unknown"
    file_name = "python312-runtime-apphost.zip"
    file_type = "zip"
    first_seen = "2026-09-17 00:03:04"
  condition:
    hash.sha256(0, filesize) == "88cd0f5f6f0ed0780b450cc53f18136cb3f8245aef432e563ca30b6ec30bbfc6"
}
```

### Sample 82: `1280ff5f2c4a59e8`

| Field | Value |
|---|---|
| SHA-256 | `1280ff5f2c4a59e8a9301d8e2eb7c2e9774ec6026a48905c52d23fb1974438bf` |
| Family label | `unknown` |
| File name | `app.pyd` |
| File type | `exe` |
| First seen | `2026-09-17 00:02:50` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, exe, Nuitka, pyd, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `885bdc5811818d7a2de49417319ebd0a` |
| SHA-1 | `f20aec8533b8b76e55f7133903fd1156213e8d89` |
| SHA-256 | `1280ff5f2c4a59e8a9301d8e2eb7c2e9774ec6026a48905c52d23fb1974438bf` |
| SHA3-384 | `d3b311bb78b184abd82c8a4ecf346f7c165fc1e88d315177e4521b0cf68aad2c6f17765c646e87b4cd6a283fde62e7b4` |
| IMPHASH | `50f9fe8df2dc9541a8395ddfc3bf57be` |
| TLSH | `T1BF85191323B40046F6F6D5F74EAA9B23DDB2F9CE1B2232D704A4EA592B83DD256DC144` |
| SSDEEP | `24576:Fs1eI/R4pxl7ekJFfBupIFfrVw5eQKAx+BUpVpIgQjGHyCNyCvaz9a:FKeoR4d7ekJFpupIFedpZVyZwm9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_1280ff5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1280ff5f2c4a59e8a9301d8e2eb7c2e9774ec6026a48905c52d23fb1974438bf"
    family = "unknown"
    file_name = "app.pyd"
    file_type = "exe"
    first_seen = "2026-09-17 00:02:50"
  condition:
    hash.sha256(0, filesize) == "1280ff5f2c4a59e8a9301d8e2eb7c2e9774ec6026a48905c52d23fb1974438bf"
}
```

### Sample 83: `64cfe4f7abbbd114`

| Field | Value |
|---|---|
| SHA-256 | `64cfe4f7abbbd114c77ca589c96cf77a43ee1a03a4b45f55de8ddfc1a06a4546` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-16 23:48:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e53598c2d642c906f72d1caa9d3610ab` |
| SHA-1 | `87cc2d624ae28d24067b9b48fa895ec5e98d4d9a` |
| SHA-256 | `64cfe4f7abbbd114c77ca589c96cf77a43ee1a03a4b45f55de8ddfc1a06a4546` |
| SHA3-384 | `25028720830523e83473f101709cdf93282e783ecb3a76379b3a2b4e87da93c77fba00d39a37842af9bd36dfdb97b229` |
| TLSH | `T1EFA35D97F401EE7DF80BD5BA04670A0AF630E3E51B930B366397BD67ED351A50826E81` |
| SSDEEP | `1536:iPhR5NhZp+huOzP6DxHd8P9foRRfZAuDbAV3GNPt8Qkra:ip3PSVWxHcqRhzhNPt8Qkra` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_64cfe4f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cfe4f7abbbd114c77ca589c96cf77a43ee1a03a4b45f55de8ddfc1a06a4546"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:45"
  condition:
    hash.sha256(0, filesize) == "64cfe4f7abbbd114c77ca589c96cf77a43ee1a03a4b45f55de8ddfc1a06a4546"
}
```

### Sample 84: `2936a273207cd8c6`

| Field | Value |
|---|---|
| SHA-256 | `2936a273207cd8c6d4818417ce1cf6004a91a4b481641053f68231432560392a` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-16 23:48:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80625e660d9fc577d23a8d829fe07b3b` |
| SHA-1 | `8763e65c0dd0d004f88c545c660495d47e2f64a1` |
| SHA-256 | `2936a273207cd8c6d4818417ce1cf6004a91a4b481641053f68231432560392a` |
| SHA3-384 | `508fd1649fe4c4c236e714081e5cf4b6976d6c433b2f14d7b22a2b1dde44828689910ca9da503d503df121e1110bd964` |
| TLSH | `T106934B02B3080E47D1A71DB0353F2BD197BEE6D121E4F689750FAB9692B6D331486EC9` |
| SSDEEP | `1536:XefrO+xXyy3U+M8JekB7T9/xtLUWnJKUBKgslCe/SNRcYJfqqS2JINlS:XGptyz+VJzB7T9/bLUAx9e/SBJOlS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_2936a273
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2936a273207cd8c6d4818417ce1cf6004a91a4b481641053f68231432560392a"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:43"
  condition:
    hash.sha256(0, filesize) == "2936a273207cd8c6d4818417ce1cf6004a91a4b481641053f68231432560392a"
}
```

### Sample 85: `451ee04f7f27631d`

| Field | Value |
|---|---|
| SHA-256 | `451ee04f7f27631d0d184be98151e83401371ae347ca1ba81d8697973656684d` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-16 23:48:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `891943b768e8b60de6214cdda87a079d` |
| SHA-1 | `cd0ffa85c77618fdddfa0e1fae633b44503f0d9a` |
| SHA-256 | `451ee04f7f27631d0d184be98151e83401371ae347ca1ba81d8697973656684d` |
| SHA3-384 | `deddbe6ea10977773d3eb97e07f862dc51eb29d98aa689204d93a9762267e1f50aaf12542b026e56213e68bc4fc18e50` |
| TLSH | `T12CC3D60ABF210FFBD85FCD3B06A9170225CC555722E9BB3A7574C928F64A21B09D3DA4` |
| SSDEEP | `1536:QhwCvdHmez3BK9LW05Biw6PmPQ4+efKmWhS4cUz9KrZ9nTDCV5bOvd7JMhN:MwCvdHmezn0nUPMu9KryXsMhN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_451ee04f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451ee04f7f27631d0d184be98151e83401371ae347ca1ba81d8697973656684d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:41"
  condition:
    hash.sha256(0, filesize) == "451ee04f7f27631d0d184be98151e83401371ae347ca1ba81d8697973656684d"
}
```

### Sample 86: `bdeeb22e0311ca8f`

| Field | Value |
|---|---|
| SHA-256 | `bdeeb22e0311ca8f724be3a46067cf868e48355d89c41ce8c511202dbfa83d34` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-16 23:48:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `985baffe5637800b25abe4bbaefa4519` |
| SHA-1 | `68f9747a8aa126929010e98c09ed980ab41a4a82` |
| SHA-256 | `bdeeb22e0311ca8f724be3a46067cf868e48355d89c41ce8c511202dbfa83d34` |
| SHA3-384 | `649aa21f92383fcbd3d534fe0d67967f925b093c923ab8aa0ffdcc513519e286fac7d93ea96c335bbd750103786c698e` |
| TLSH | `T105A34B36B874192BC4D4A47E22F74721F5F247D925A8861E7EB20D8EBF206403653BB6` |
| SSDEEP | `1536:a7ZpFghRWSbbmLOnzavBUgOl2OpT30kbekbRlM5RAPwTTnt0oXj:bbbmPTO930bkbRl886Xj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_bdeeb22e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdeeb22e0311ca8f724be3a46067cf868e48355d89c41ce8c511202dbfa83d34"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:40"
  condition:
    hash.sha256(0, filesize) == "bdeeb22e0311ca8f724be3a46067cf868e48355d89c41ce8c511202dbfa83d34"
}
```

### Sample 87: `6b357f5c166c3297`

| Field | Value |
|---|---|
| SHA-256 | `6b357f5c166c3297b75b804eb07d51141a4da4633a16dd28bfd42054c893950e` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-16 23:48:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bbe64ce51228f05193f5a18b0afb0f7` |
| SHA-1 | `d8d67e6fdc5c7486ebb49d1c9365b053843b16c5` |
| SHA-256 | `6b357f5c166c3297b75b804eb07d51141a4da4633a16dd28bfd42054c893950e` |
| SHA3-384 | `9dcdc3b9a7c1d6b76606ecc6c94007aebce6cc1351190cc544800417a74a60a16b757d3f5d413c12a8e39726f7ec4fcb` |
| TLSH | `T1AD83AD32EA292D44C0455570B0B98F395B73A5C083476FB66AFAC6785047DACF90AFF8` |
| SSDEEP | `1536:UenMpsd6H316K/1hoNJXa+GlbDKu4JlvqjwKqad+WC7s:UeAsdukuhoNJVwbmuUqjLjwWis` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_6b357f5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b357f5c166c3297b75b804eb07d51141a4da4633a16dd28bfd42054c893950e"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:38"
  condition:
    hash.sha256(0, filesize) == "6b357f5c166c3297b75b804eb07d51141a4da4633a16dd28bfd42054c893950e"
}
```

### Sample 88: `e58d5583cb71b8e3`

| Field | Value |
|---|---|
| SHA-256 | `e58d5583cb71b8e3f3a95ef7cc9a0ba4fba76fa4ca03ebd7e8e5a91810f6250d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 23:42:01` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3809b0830a002431b4ce079ac2990c06` |
| SHA-1 | `47ae635578a65a43a00734a70195ef75fcec1126` |
| SHA-256 | `e58d5583cb71b8e3f3a95ef7cc9a0ba4fba76fa4ca03ebd7e8e5a91810f6250d` |
| SHA3-384 | `cdc87abe0243f8adb37929df96b3af196342552582015241b58ae08089e5aa3bd602ee1a991f5679fa8953fb737d6876` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16B62D786D8A22FADDE4F80703A11F9687D7532E58665A9F3D7928C345DA38D00428FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UH9XBM:fKOe2/7c9sN3zfZR1m+RG49X6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_e58d5583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e58d5583cb71b8e3f3a95ef7cc9a0ba4fba76fa4ca03ebd7e8e5a91810f6250d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:42:01"
  condition:
    hash.sha256(0, filesize) == "e58d5583cb71b8e3f3a95ef7cc9a0ba4fba76fa4ca03ebd7e8e5a91810f6250d"
}
```

### Sample 89: `d45f4103caae9f2c`

| Field | Value |
|---|---|
| SHA-256 | `d45f4103caae9f2cf203a6cfbb1b0c075ab64208ff7c6af0b3e5b3232b02f91a` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 23:41:06` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d3a7e6388dd4b12cb4e28a2ea7f1f7d` |
| SHA-1 | `162b0cc3b57292aeaa020de2e2139609b1d3d05c` |
| SHA-256 | `d45f4103caae9f2cf203a6cfbb1b0c075ab64208ff7c6af0b3e5b3232b02f91a` |
| SHA3-384 | `37c371430c9930693db6bc3568ef020cdc03928bd32993359cc339cc26b5f4124826ba0d0febd0f343078657ab70276a` |
| IMPHASH | `1dcd477cce07724ec6b817b3be71540e` |
| TLSH | `T15707338276D678F5FC369238C893955663763C8347E6C6EB23E809166D136E4063FB32` |
| SSDEEP | `393216:l/uC7hHTodRGkX4HZZVjloFaaab+BSazc+4KszF1:QCl0LhXWoFaaab0SaA/f` |
| ICON-DHASH | `f0d4820d8e8ef4f8` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_089_d45f4103
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45f4103caae9f2cf203a6cfbb1b0c075ab64208ff7c6af0b3e5b3232b02f91a"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:41:06"
  condition:
    hash.sha256(0, filesize) == "d45f4103caae9f2cf203a6cfbb1b0c075ab64208ff7c6af0b3e5b3232b02f91a"
}
```

### Sample 90: `a06159034f2e9d1d`

| Field | Value |
|---|---|
| SHA-256 | `a06159034f2e9d1db463a3a63349758145f88f7a70dbe16824bc46d0d49e397c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 23:37:12` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06d8971b22f2aaa2aa5875c458826545` |
| SHA-1 | `5a4fcca9d53f34d86ff9b7df84e1de1fa7eae103` |
| SHA-256 | `a06159034f2e9d1db463a3a63349758145f88f7a70dbe16824bc46d0d49e397c` |
| SHA3-384 | `de23119231ada83151f97f9d6acfdaec03f289c201562df86d394c6ea23f7083025dc58f35100b0851fef585a8762953` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12A62C886D8A25F6CDECEC0703A15F8787E757690856A99E3D7A18C345A63DD00024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Us5eBM:fKOe2/7c9sN3zfZR1m+RGP5e6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_a0615903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a06159034f2e9d1db463a3a63349758145f88f7a70dbe16824bc46d0d49e397c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:37:12"
  condition:
    hash.sha256(0, filesize) == "a06159034f2e9d1db463a3a63349758145f88f7a70dbe16824bc46d0d49e397c"
}
```

### Sample 91: `1e4e63f83a5871c8`

| Field | Value |
|---|---|
| SHA-256 | `1e4e63f83a5871c8c94d804572f7455a5472fe73f102208e8a3029582769aa81` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 23:31:53` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e03312389473d846b2fdbd805d22593` |
| SHA-1 | `cca688b6052a37059ed2f72768b42d38188772d6` |
| SHA-256 | `1e4e63f83a5871c8c94d804572f7455a5472fe73f102208e8a3029582769aa81` |
| SHA3-384 | `c475ad662b412778f21b266f7332317d1fcd85bade39a8d3248efd92e2cec6a7a916c93c8f95bbeed60b0a2dd83083cb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17162C686D8E23E5CEE4F80703A11F838B97536908665A9F3D7828C795AA3DD04524EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U7EHBM:fKOe2/7c9sN3zfZR1m+RGvH6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_1e4e63f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e4e63f83a5871c8c94d804572f7455a5472fe73f102208e8a3029582769aa81"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:31:53"
  condition:
    hash.sha256(0, filesize) == "1e4e63f83a5871c8c94d804572f7455a5472fe73f102208e8a3029582769aa81"
}
```

### Sample 92: `02cc5e354a59888c`

| Field | Value |
|---|---|
| SHA-256 | `02cc5e354a59888caf2a700a7c7423bab396df16cd031994df046bd073fa2978` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-09-16 23:31:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e233a730f8063e1e9015138f3bdb608e` |
| SHA-1 | `005622746997a62f6f2f8ff5c0c2cb213f2086f6` |
| SHA-256 | `02cc5e354a59888caf2a700a7c7423bab396df16cd031994df046bd073fa2978` |
| SHA3-384 | `27a6f670265644225080440e050f291f375abdcb5201fe004a538aa5ab8626a3ad26872aeea07ff6433d43bce5a5c811` |
| TLSH | `T196D4AE16F999EE63C5B7963AC4A7C6D17232E85E1BB3C316210D513E38172398F1EB84` |
| TELFHASH | `t166317a61e51afd251692cbccebc4b366c4bae9004a0e3c67c5b0442d9b30197278fdea` |
| SSDEEP | `12288:OALZUp0jgpii/aTVsP76GWIGz3oFyVBA4pzeqoekMucrJWl7:9f1jBzNuc1Wl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_02cc5e35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02cc5e354a59888caf2a700a7c7423bab396df16cd031994df046bd073fa2978"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-16 23:31:33"
  condition:
    hash.sha256(0, filesize) == "02cc5e354a59888caf2a700a7c7423bab396df16cd031994df046bd073fa2978"
}
```

### Sample 93: `b95e802eb09c9e7a`

| Field | Value |
|---|---|
| SHA-256 | `b95e802eb09c9e7aad64e142591d2e7b2bea5c8b751f31d82ac6d193bfd95d1b` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-09-16 23:31:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bb649d150f8eb590ae843a2703b2966` |
| SHA-1 | `f53cb8061511295c006e7c14abd5e10ee834bd52` |
| SHA-256 | `b95e802eb09c9e7aad64e142591d2e7b2bea5c8b751f31d82ac6d193bfd95d1b` |
| SHA3-384 | `7836bca4f42c4506ec51d975fa090b661664be52d99a97b324f37e1db0f41849f2acc06e01eab0a31afca1cc824513b0` |
| TLSH | `T1CB058EA277164F64D3A5C67109F3CB28A5C4216609F765CAD7A3CA207A013EC6C2FFD9` |
| SSDEEP | `12288:HbfkdOh5QHnX4mNFDKTJhtjWsO+wP8w3Ev2LUW9TTlny5mSfuWcc:jkEm/KtK+wy2LUW9fl89d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_b95e802e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95e802eb09c9e7aad64e142591d2e7b2bea5c8b751f31d82ac6d193bfd95d1b"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-16 23:31:32"
  condition:
    hash.sha256(0, filesize) == "b95e802eb09c9e7aad64e142591d2e7b2bea5c8b751f31d82ac6d193bfd95d1b"
}
```

### Sample 94: `7443284aa2c52b64`

| Field | Value |
|---|---|
| SHA-256 | `7443284aa2c52b644026bf9d6913ac25c190e82af7cef6db5dd7909e0d9210ba` |
| Family label | `unknown` |
| File name | `update.mips` |
| File type | `elf` |
| First seen | `2026-09-16 23:31:25` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10c29ba5086fc07276896cf585c06e27` |
| SHA-1 | `d024546b6ee5aca172b76c68158adc6a779c3242` |
| SHA-256 | `7443284aa2c52b644026bf9d6913ac25c190e82af7cef6db5dd7909e0d9210ba` |
| SHA3-384 | `f17705ab2a637508267384f52488f19d2e2a1ce3a590716c3ef51fa978c6277f18c0679875818403c9d78797c0ccb906` |
| TLSH | `T10BE19FEA678633A3C45A3DB3135905041069B8FD5F074DBB49CD67B6B40DCB5835213E` |
| SSDEEP | `96:Z+woWdAeDLbkfD17GURfZKlfljxZDkn7SBoeqOUmYKELmgt7YAqQJes9Ar8g2lFu:aoG71MlVx1k2UzKkEc7t6MTSrf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_7443284a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7443284aa2c52b644026bf9d6913ac25c190e82af7cef6db5dd7909e0d9210ba"
    family = "unknown"
    file_name = "update.mips"
    file_type = "elf"
    first_seen = "2026-09-16 23:31:25"
  condition:
    hash.sha256(0, filesize) == "7443284aa2c52b644026bf9d6913ac25c190e82af7cef6db5dd7909e0d9210ba"
}
```

### Sample 95: `ab7341a28293c560`

| Field | Value |
|---|---|
| SHA-256 | `ab7341a28293c5607f3701879c00f4ca4f315611ff8fc0246f2401228742ee7d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 23:29:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51d366088f28bfa43f01bd1c3149622d` |
| SHA-1 | `d78b1a4248624153635514bffdfc5a36d410720d` |
| SHA-256 | `ab7341a28293c5607f3701879c00f4ca4f315611ff8fc0246f2401228742ee7d` |
| SHA3-384 | `0cf20f9da815231c2a2f375326a7626cc7305b7f977c9690947d8229ccf266ec7be0c6bd579f2b45424166916c10704b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CE62C79ADA922F5CCE4F80703E11FD28AD747695866559E3DB828C305EA38E14434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJY5BM:fKOe2/7c9sN3zfZR1m+RGwY56C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_ab7341a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab7341a28293c5607f3701879c00f4ca4f315611ff8fc0246f2401228742ee7d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:29:27"
  condition:
    hash.sha256(0, filesize) == "ab7341a28293c5607f3701879c00f4ca4f315611ff8fc0246f2401228742ee7d"
}
```

### Sample 96: `a98d913fc773efa9`

| Field | Value |
|---|---|
| SHA-256 | `a98d913fc773efa9a950bc11fcb170d602cb624963e5e3086c82cf6dc8b42c37` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-09-16 23:27:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b488ddeb1005c38e23cfd1575049d60` |
| SHA-1 | `c1b0da05623b2d5a3da1ff71e90dcfbdb7d4a06f` |
| SHA-256 | `a98d913fc773efa9a950bc11fcb170d602cb624963e5e3086c82cf6dc8b42c37` |
| SHA3-384 | `0682cda611206fdb5b19f001307267ff6605e408fd9f265a1d16f59fee406e4a1e1089efd0376d6a1283c22275b0a6c0` |
| TLSH | `T1BB05F717EB510DB6E859CCB311AA23406DCE527B91EA33A7B935C950FD9980B06F3DE0` |
| SSDEEP | `6144:hclb4gYQEQy6x8AMgCuBjxPpCsLMnPwGEeZ29:hclb4gC6x8AMgh0s4PwAA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_a98d913f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98d913fc773efa9a950bc11fcb170d602cb624963e5e3086c82cf6dc8b42c37"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-09-16 23:27:23"
  condition:
    hash.sha256(0, filesize) == "a98d913fc773efa9a950bc11fcb170d602cb624963e5e3086c82cf6dc8b42c37"
}
```

### Sample 97: `38670c27775aeb5d`

| Field | Value |
|---|---|
| SHA-256 | `38670c27775aeb5d6f548e971fd22c6d10eb61a6e44f1003d8fd7c909c0799d4` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-16 23:23:13` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34e9910496a68d1d6ca3bbb7bb683cf9` |
| SHA-1 | `a6848d1dfac8688666f5930afba3259f1ed5f987` |
| SHA-256 | `38670c27775aeb5d6f548e971fd22c6d10eb61a6e44f1003d8fd7c909c0799d4` |
| SHA3-384 | `db7eff87942170e6119f0ea7a8544f3ce3779d252e21487094d791b0b40f36025c97ae1160ff0511cdfe6cbf417acdc4` |
| TLSH | `T1EE137D6566853C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C19A9CD21971D` |
| SSDEEP | `768:/XRWNGxVU9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:5lxHco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_097_38670c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38670c27775aeb5d6f548e971fd22c6d10eb61a6e44f1003d8fd7c909c0799d4"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 23:23:13"
  condition:
    hash.sha256(0, filesize) == "38670c27775aeb5d6f548e971fd22c6d10eb61a6e44f1003d8fd7c909c0799d4"
}
```

### Sample 98: `28853653cfba4d9a`

| Field | Value |
|---|---|
| SHA-256 | `28853653cfba4d9a93f25a90a91ab851e1c38d639a6b5e8078342325d334f529` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-16 23:23:12` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa1cb9420a541c7cbc2b1813b447f6cd` |
| SHA-1 | `79a407e763930a39b311dda67f24022ec30f922d` |
| SHA-256 | `28853653cfba4d9a93f25a90a91ab851e1c38d639a6b5e8078342325d334f529` |
| SHA3-384 | `fc5998e3c28edec8c487a506a65ad518b8e5baab3aae9e768b98675ad39fe2ab5b2fc142f0af399ee794fd43dbce9e4f` |
| TLSH | `T1B9136D6566843C24AE9988371D7E2F0CBDB983E5310851DDBFCB3CF58C49A9CA219B1D` |
| SSDEEP | `768:e6rDTPjHzp9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:tr3vico` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_098_28853653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28853653cfba4d9a93f25a90a91ab851e1c38d639a6b5e8078342325d334f529"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 23:23:12"
  condition:
    hash.sha256(0, filesize) == "28853653cfba4d9a93f25a90a91ab851e1c38d639a6b5e8078342325d334f529"
}
```

### Sample 99: `64bf8990b84d3480`

| Field | Value |
|---|---|
| SHA-256 | `64bf8990b84d3480b0f5585ec932d96d719e6e8e7285a0705cc8054cdbc46663` |
| Family label | `unknown` |
| File name | `release-x64.exe` |
| File type | `exe` |
| First seen | `2026-09-16 23:18:21` |
| Reporter | `nevermorelove` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01b031316faaacdd45d18c53581b3f23` |
| SHA-256 | `64bf8990b84d3480b0f5585ec932d96d719e6e8e7285a0705cc8054cdbc46663` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_64bf8990
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bf8990b84d3480b0f5585ec932d96d719e6e8e7285a0705cc8054cdbc46663"
    family = "unknown"
    file_name = "release-x64.exe"
    file_type = "exe"
    first_seen = "2026-09-16 23:18:21"
  condition:
    hash.sha256(0, filesize) == "64bf8990b84d3480b0f5585ec932d96d719e6e8e7285a0705cc8054cdbc46663"
}
```

### Sample 100: `71ad71b4015e6329`

| Field | Value |
|---|---|
| SHA-256 | `71ad71b4015e63291ea4fc8b6cab6260cf1198b36fb9767d4724df6f7f269689` |
| Family label | `unknown` |
| File name | `main.exe` |
| File type | `exe` |
| First seen | `2026-09-16 23:18:13` |
| Reporter | `nevermorelove` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `107480caffe51ef6dc096fe8e5ba27a8` |
| SHA-256 | `71ad71b4015e63291ea4fc8b6cab6260cf1198b36fb9767d4724df6f7f269689` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_71ad71b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71ad71b4015e63291ea4fc8b6cab6260cf1198b36fb9767d4724df6f7f269689"
    family = "unknown"
    file_name = "main.exe"
    file_type = "exe"
    first_seen = "2026-09-16 23:18:13"
  condition:
    hash.sha256(0, filesize) == "71ad71b4015e63291ea4fc8b6cab6260cf1198b36fb9767d4724df6f7f269689"
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
 * Generated: 2026-09-17T04:59:30.060271+00:00
 */

rule MalwareBazaar_JOMANGY_001_b5a68536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5a68536fe3921788dd64d9e792eeac5cdd4b25e50cec28d9598efaf7452e1a9"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 04:55:35"
  condition:
    hash.sha256(0, filesize) == "b5a68536fe3921788dd64d9e792eeac5cdd4b25e50cec28d9598efaf7452e1a9"
}

rule MalwareBazaar_unknown_002_6563b04c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779"
    family = "unknown"
    file_name = "6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779.sh"
    file_type = "sh"
    first_seen = "2026-09-17 04:52:33"
  condition:
    hash.sha256(0, filesize) == "6563b04cdd56bed19a23dfcea06759a463906d46a148ac837f4e6aa759d37779"
}

rule MalwareBazaar_unknown_003_6ed67e01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ed67e01f2dfeb56f26811658a81982e3106baaee2031abeac604c2b309152c0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:47:15"
  condition:
    hash.sha256(0, filesize) == "6ed67e01f2dfeb56f26811658a81982e3106baaee2031abeac604c2b309152c0"
}

rule MalwareBazaar_unknown_004_96fe8031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96fe80312f79e679655922b0a93fd3794f6c6e8f9140c1e60abbd55257df1155"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:44:49"
  condition:
    hash.sha256(0, filesize) == "96fe80312f79e679655922b0a93fd3794f6c6e8f9140c1e60abbd55257df1155"
}

rule MalwareBazaar_unknown_005_851cf004
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "851cf00451adf72a80fc5d6c23db0024e2c98e371cff3e149af91a1473b5fd92"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:42:23"
  condition:
    hash.sha256(0, filesize) == "851cf00451adf72a80fc5d6c23db0024e2c98e371cff3e149af91a1473b5fd92"
}

rule MalwareBazaar_unknown_006_c3efcb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3efcb33f06e34624a1168a60d51f16e4a0c1107d16ba603f7868e62835b5393"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:39:29"
  condition:
    hash.sha256(0, filesize) == "c3efcb33f06e34624a1168a60d51f16e4a0c1107d16ba603f7868e62835b5393"
}

rule MalwareBazaar_unknown_007_7008af80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7008af80cb565d40b5c0a05e27d8f68b8596218f7010e8120fcdcbeab855411d"
    family = "unknown"
    file_name = "Kohzan Maru VI Vessel Q88.js"
    file_type = "js"
    first_seen = "2026-09-17 04:38:24"
  condition:
    hash.sha256(0, filesize) == "7008af80cb565d40b5c0a05e27d8f68b8596218f7010e8120fcdcbeab855411d"
}

rule MalwareBazaar_unknown_008_567dbac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "567dbac64a05d549505a597dcfd357eebd02e9b0b6000371edc43f930ec8052e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:36:44"
  condition:
    hash.sha256(0, filesize) == "567dbac64a05d549505a597dcfd357eebd02e9b0b6000371edc43f930ec8052e"
}

rule MalwareBazaar_Mirai_009_28388aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28388aad9b33b0d2ffa985ef62c8e2fa67f2a147475f575caa411cdebebb0b8c"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-09-17 04:34:41"
  condition:
    hash.sha256(0, filesize) == "28388aad9b33b0d2ffa985ef62c8e2fa67f2a147475f575caa411cdebebb0b8c"
}

rule MalwareBazaar_JOMANGY_010_b5459a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5459a6ed51aa6ca1536a9f807a12551ce8679ff13d6f6f001706caf6259adaa"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 04:34:40"
  condition:
    hash.sha256(0, filesize) == "b5459a6ed51aa6ca1536a9f807a12551ce8679ff13d6f6f001706caf6259adaa"
}

rule MalwareBazaar_unknown_011_1b03ce50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b03ce50b5b6fd1a5368388e5c2243eb30e113029981de2b713fe2d4d3ebbac4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 04:34:28"
  condition:
    hash.sha256(0, filesize) == "1b03ce50b5b6fd1a5368388e5c2243eb30e113029981de2b713fe2d4d3ebbac4"
}

rule MalwareBazaar_unknown_012_1ab16260
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09"
    family = "unknown"
    file_name = "1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09.sh"
    file_type = "sh"
    first_seen = "2026-09-17 04:28:40"
  condition:
    hash.sha256(0, filesize) == "1ab16260eb6253ce201194f28cd2531a40b2ff99efbba0cc2bd403b3137d3a09"
}

rule MalwareBazaar_Mirai_013_baf04b14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf04b1406f12ef26a61367823663e23e8348bb4477adcddf45afd8c91fa43af"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-17 04:25:47"
  condition:
    hash.sha256(0, filesize) == "baf04b1406f12ef26a61367823663e23e8348bb4477adcddf45afd8c91fa43af"
}

rule MalwareBazaar_unknown_014_47e964af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd"
    family = "unknown"
    file_name = "47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd"
    file_type = "elf"
    first_seen = "2026-09-17 04:17:18"
  condition:
    hash.sha256(0, filesize) == "47e964af9b5509b43ce4797be8301352ec13539ed2a46bfa07ab2e892f795dcd"
}

rule MalwareBazaar_unknown_015_1937a7d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466"
    family = "unknown"
    file_name = "1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466"
    file_type = "elf"
    first_seen = "2026-09-17 04:17:12"
  condition:
    hash.sha256(0, filesize) == "1937a7d65d55cf2401faa5b3f5aeb1f8381385d457783d9d520d5266ea8ab466"
}

rule MalwareBazaar_unknown_016_c0f2e2e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44"
    family = "unknown"
    file_name = "c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44.sh"
    file_type = "sh"
    first_seen = "2026-09-17 04:16:35"
  condition:
    hash.sha256(0, filesize) == "c0f2e2e94e578d768233ba99c985d99001c449739936e4bef7be4b0a1e3e0a44"
}

rule MalwareBazaar_unknown_017_15eeb52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15eeb52af2fcc5e68ebaf9f059b9afe3917d60b3d727b36a106722a05755e36e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-17 04:13:30"
  condition:
    hash.sha256(0, filesize) == "15eeb52af2fcc5e68ebaf9f059b9afe3917d60b3d727b36a106722a05755e36e"
}

rule MalwareBazaar_unknown_018_36fa0488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb"
    family = "unknown"
    file_name = "36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:58:45"
  condition:
    hash.sha256(0, filesize) == "36fa048836371a926429b172dc72c07843a03385c7196d3fa9d44df4099dbbdb"
}

rule MalwareBazaar_unknown_019_d26f403f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a"
    family = "unknown"
    file_name = "d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:58:43"
  condition:
    hash.sha256(0, filesize) == "d26f403f40ee4a05abc5fbc53ea2bf7c2aae5adca590c2aa91b8f896418f474a"
}

rule MalwareBazaar_unknown_020_bbd040d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb"
    family = "unknown"
    file_name = "bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:54:26"
  condition:
    hash.sha256(0, filesize) == "bbd040d2e5b982d2ed3300f2652be8c3763c20035589536a9ca4a7a1a9c19cbb"
}

rule MalwareBazaar_unknown_021_41baa062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09"
    family = "unknown"
    file_name = "41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:54:24"
  condition:
    hash.sha256(0, filesize) == "41baa062d7079b9595d9ec18ff35cdf5eb71265cfbcd1581d71c65d3a41b9b09"
}

rule MalwareBazaar_JOMANGY_022_de4940e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de4940e9d5d87a133b2a5ae127630f6db7d92c289eed77298ef8d319fc986c50"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-17 03:54:23"
  condition:
    hash.sha256(0, filesize) == "de4940e9d5d87a133b2a5ae127630f6db7d92c289eed77298ef8d319fc986c50"
}

rule MalwareBazaar_unknown_023_98de96dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0"
    family = "unknown"
    file_name = "98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0.sh"
    file_type = "sh"
    first_seen = "2026-09-17 03:49:33"
  condition:
    hash.sha256(0, filesize) == "98de96dc2fbd79e23eb6e07676cb453eb9efb14d54fb908f382775fda97d4bb0"
}

rule MalwareBazaar_Mirai_024_34431659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34431659c7b37339b7d9774204d55b4fc68d3e970eaa76056e8be11d6eec7780"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-09-17 03:49:32"
  condition:
    hash.sha256(0, filesize) == "34431659c7b37339b7d9774204d55b4fc68d3e970eaa76056e8be11d6eec7780"
}

rule MalwareBazaar_unknown_025_9dd565d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9"
    family = "unknown"
    file_name = "9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:35"
  condition:
    hash.sha256(0, filesize) == "9dd565d2bb8a2e4f3ac6253e4a1a70fab0436f780c43b45da3e7946d383ac4d9"
}

rule MalwareBazaar_unknown_026_d722a46e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c"
    family = "unknown"
    file_name = "d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:27"
  condition:
    hash.sha256(0, filesize) == "d722a46e3c3acfd16f83a466dc21290ef041d51504dc050382cbadaeffed2e4c"
}

rule MalwareBazaar_unknown_027_05c667f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e"
    family = "unknown"
    file_name = "05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:20"
  condition:
    hash.sha256(0, filesize) == "05c667f45f5df631a8a4828f4e78b5479545ae254f46a309c9feabf22a40320e"
}

rule MalwareBazaar_Mirai_028_10b55876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560"
    family = "Mirai"
    file_name = "10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560"
    file_type = "elf"
    first_seen = "2026-09-17 03:17:14"
  condition:
    hash.sha256(0, filesize) == "10b55876b694b625abb1dd0e959d2fc04106fcb4467eb8e99af4b609d0da2560"
}

rule MalwareBazaar_unknown_029_775678b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "775678b3536af460c08b77224d540d909a946409f40ee0db03eb1f8d35e9c4b7"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-17 03:13:14"
  condition:
    hash.sha256(0, filesize) == "775678b3536af460c08b77224d540d909a946409f40ee0db03eb1f8d35e9c4b7"
}

rule MalwareBazaar_JOMANGY_030_004603a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "004603a25e2e27251b14d62c726d3333da05a0f49d90f7fbe444b2868733dc82"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 03:09:40"
  condition:
    hash.sha256(0, filesize) == "004603a25e2e27251b14d62c726d3333da05a0f49d90f7fbe444b2868733dc82"
}

rule MalwareBazaar_unknown_031_9db957aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5"
    family = "unknown"
    file_name = "9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5"
    file_type = "elf"
    first_seen = "2026-09-17 02:52:32"
  condition:
    hash.sha256(0, filesize) == "9db957aab489232fbd081674b6317e9c32a30ea1d6ee3572b275a3c2b72994b5"
}

rule MalwareBazaar_Prometei_032_dc8caaee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102"
    family = "Prometei"
    file_name = "dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102"
    file_type = "elf"
    first_seen = "2026-09-17 02:51:41"
  condition:
    hash.sha256(0, filesize) == "dc8caaee7a1fd32f9f54961e161b1209b458233b509ecda9900090c179c83102"
}

rule MalwareBazaar_unknown_033_9743f652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd"
    family = "unknown"
    file_name = "9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd"
    file_type = "exe"
    first_seen = "2026-09-17 02:51:18"
  condition:
    hash.sha256(0, filesize) == "9743f6525b96c60db418385ae9d035c8251c62811a381063642bdc9703f6b5bd"
}

rule MalwareBazaar_unknown_034_ac4bab56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833"
    family = "unknown"
    file_name = "ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833.sh"
    file_type = "sh"
    first_seen = "2026-09-17 02:39:16"
  condition:
    hash.sha256(0, filesize) == "ac4bab56a5cb00a87d7fdb911d14201a50f01a29e4fa2ff1947acb9fe360a833"
}

rule MalwareBazaar_unknown_035_b80a275e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b80a275eb2c3abe0f0a497eac27c908628f3472f9a3de0e8f4d7518e4c965a2d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:23:22"
  condition:
    hash.sha256(0, filesize) == "b80a275eb2c3abe0f0a497eac27c908628f3472f9a3de0e8f4d7518e4c965a2d"
}

rule MalwareBazaar_unknown_036_3d76d141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d76d141c05ca1e5f354e489c81b1266e844043fa4c50de0ce41560c3b960881"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:20:31"
  condition:
    hash.sha256(0, filesize) == "3d76d141c05ca1e5f354e489c81b1266e844043fa4c50de0ce41560c3b960881"
}

rule MalwareBazaar_unknown_037_c05ab4ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c05ab4efaa83407081c78bd9c4da34ca5fd004e595add11b26e2905463d530c5"
    family = "unknown"
    file_name = "PlatinumRSVP.msi"
    file_type = "msi"
    first_seen = "2026-09-17 02:19:53"
  condition:
    hash.sha256(0, filesize) == "c05ab4efaa83407081c78bd9c4da34ca5fd004e595add11b26e2905463d530c5"
}

rule MalwareBazaar_unknown_038_26419c13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26419c134a60de42e1b72663b5e27623ea7237c3d160846104af440c39b35cbe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:18:18"
  condition:
    hash.sha256(0, filesize) == "26419c134a60de42e1b72663b5e27623ea7237c3d160846104af440c39b35cbe"
}

rule MalwareBazaar_unknown_039_4f8c7666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f8c76660cb28a7b8b59b4bdea358c9fd101b6a1999213049defec1fa69cef1c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:18:12"
  condition:
    hash.sha256(0, filesize) == "4f8c76660cb28a7b8b59b4bdea358c9fd101b6a1999213049defec1fa69cef1c"
}

rule MalwareBazaar_unknown_040_d9c70679
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991"
    family = "unknown"
    file_name = "d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991"
    file_type = "elf"
    first_seen = "2026-09-17 02:17:25"
  condition:
    hash.sha256(0, filesize) == "d9c70679d03602fc1d186bc6547868b62e62135e3f180edde6746d7bd135e991"
}

rule MalwareBazaar_unknown_041_fc1db604
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88"
    family = "unknown"
    file_name = "fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88"
    file_type = "elf"
    first_seen = "2026-09-17 02:17:19"
  condition:
    hash.sha256(0, filesize) == "fc1db604acc536bcb4733a5447cfe8ae6b492ba7cecb99dc6ff94310c9d32b88"
}

rule MalwareBazaar_unknown_042_068e0c4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1"
    family = "unknown"
    file_name = "068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1"
    file_type = "elf"
    first_seen = "2026-09-17 02:17:12"
  condition:
    hash.sha256(0, filesize) == "068e0c4c8a5d4a9674ccfca5ad310f35ec93f61d12ff712ffcf2bac15f369cd1"
}

rule MalwareBazaar_unknown_043_354dbe76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "354dbe764cc11cdbe73ab6439f00cd01e4ef70b1ab17dece1c853d28e89d600d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:15:57"
  condition:
    hash.sha256(0, filesize) == "354dbe764cc11cdbe73ab6439f00cd01e4ef70b1ab17dece1c853d28e89d600d"
}

rule MalwareBazaar_unknown_044_2dd4d23f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd4d23f5ebf25492f62fc9b2db0ec48c632825a6f2ff189b844b72f8c233a0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:15:25"
  condition:
    hash.sha256(0, filesize) == "2dd4d23f5ebf25492f62fc9b2db0ec48c632825a6f2ff189b844b72f8c233a0e"
}

rule MalwareBazaar_unknown_045_b1c921e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1c921e71f896bed283a084b7a95d9b2d326aa8a902ad0e65e143caf897f2c5d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:13:00"
  condition:
    hash.sha256(0, filesize) == "b1c921e71f896bed283a084b7a95d9b2d326aa8a902ad0e65e143caf897f2c5d"
}

rule MalwareBazaar_unknown_046_e98395e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98395e4f0c1b1a62ae5002f09c22d31d134f5bc6a3b1093d63df4fb9d89c2d2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 02:10:33"
  condition:
    hash.sha256(0, filesize) == "e98395e4f0c1b1a62ae5002f09c22d31d134f5bc6a3b1093d63df4fb9d89c2d2"
}

rule MalwareBazaar_JOMANGY_047_3bd47c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bd47c0e22be6deca2d388cdfce57c3ee0ddfd7edcb2b950b11127c20ac63720"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 02:04:18"
  condition:
    hash.sha256(0, filesize) == "3bd47c0e22be6deca2d388cdfce57c3ee0ddfd7edcb2b950b11127c20ac63720"
}

rule MalwareBazaar_GuLoader_048_decd9cec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "decd9cec9001b918b9cb930b3ed840e4446c61bd8e2279177ae090fd103818a6"
    family = "GuLoader"
    file_name = "Skovtr.vbs"
    file_type = "vbs"
    first_seen = "2026-09-17 02:03:37"
  condition:
    hash.sha256(0, filesize) == "decd9cec9001b918b9cb930b3ed840e4446c61bd8e2279177ae090fd103818a6"
}

rule MalwareBazaar_JOMANGY_049_044f045e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044f045e4eded22db7a1df66644133c9dedf2d408caa1fcaad2c4a36a3d9a6d2"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-17 01:59:33"
  condition:
    hash.sha256(0, filesize) == "044f045e4eded22db7a1df66644133c9dedf2d408caa1fcaad2c4a36a3d9a6d2"
}

rule MalwareBazaar_unknown_050_e5a560b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5a560b673e6cda0c141f42b3b5e4e39eeedab62ecc97cd7f1f7d9f2ba3cdc60"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:51:12"
  condition:
    hash.sha256(0, filesize) == "e5a560b673e6cda0c141f42b3b5e4e39eeedab62ecc97cd7f1f7d9f2ba3cdc60"
}

rule MalwareBazaar_unknown_051_14e4ec27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14e4ec273e801244be442486bee870b4598eb3c55c8455f73b46b6776e961945"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:48:50"
  condition:
    hash.sha256(0, filesize) == "14e4ec273e801244be442486bee870b4598eb3c55c8455f73b46b6776e961945"
}

rule MalwareBazaar_unknown_052_d4118662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4118662e8bf1205dc79037da13b99cf4cc18544c5b2bb3227f51bc4bf8d2324"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:46:28"
  condition:
    hash.sha256(0, filesize) == "d4118662e8bf1205dc79037da13b99cf4cc18544c5b2bb3227f51bc4bf8d2324"
}

rule MalwareBazaar_unknown_053_3ea5c705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ea5c705b933852d96c1ad160739dfeb2b614d526d684fc1b83a64f067bd9d7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:41:52"
  condition:
    hash.sha256(0, filesize) == "3ea5c705b933852d96c1ad160739dfeb2b614d526d684fc1b83a64f067bd9d7b"
}

rule MalwareBazaar_unknown_054_fba460aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba460aa8917b70a79affe248e7f2287672d562c9d2815948641835a7f461f2c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:37:10"
  condition:
    hash.sha256(0, filesize) == "fba460aa8917b70a79affe248e7f2287672d562c9d2815948641835a7f461f2c"
}

rule MalwareBazaar_unknown_055_74818afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74818afc20636033da8b02151d8226e6cc5dcc085a47e7416341120c79ac8ef7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:36:29"
  condition:
    hash.sha256(0, filesize) == "74818afc20636033da8b02151d8226e6cc5dcc085a47e7416341120c79ac8ef7"
}

rule MalwareBazaar_unknown_056_6e87682b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb"
    family = "unknown"
    file_name = "6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb"
    file_type = "elf"
    first_seen = "2026-09-17 01:35:25"
  condition:
    hash.sha256(0, filesize) == "6e87682bbd1ec48d6ab7ae3da926d5b178fd90de1a3d02d684dd2a2c681f7bdb"
}

rule MalwareBazaar_unknown_057_c4212a5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4212a5c75d9af22cfa1cacdf7ef46172d9808ad12978e9fb9fbeff7d591e3e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:34:46"
  condition:
    hash.sha256(0, filesize) == "c4212a5c75d9af22cfa1cacdf7ef46172d9808ad12978e9fb9fbeff7d591e3e1"
}

rule MalwareBazaar_unknown_058_b595b2a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b595b2a6e6884fabc556a84f0cb75fe8625aa685dc11f8de3f905fac0cdb8c90"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:34:00"
  condition:
    hash.sha256(0, filesize) == "b595b2a6e6884fabc556a84f0cb75fe8625aa685dc11f8de3f905fac0cdb8c90"
}

rule MalwareBazaar_JOMANGY_059_afa9fcf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afa9fcf6e7524c6c03aaeea0ee1878617088368956c0612f4091590b43f4c196"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-17 01:33:33"
  condition:
    hash.sha256(0, filesize) == "afa9fcf6e7524c6c03aaeea0ee1878617088368956c0612f4091590b43f4c196"
}

rule MalwareBazaar_unknown_060_e3a0147b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3a0147b49398d983c8d65a9c619bd7e4c30ad58109323efcf2db6e9d401e9cd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:32:27"
  condition:
    hash.sha256(0, filesize) == "e3a0147b49398d983c8d65a9c619bd7e4c30ad58109323efcf2db6e9d401e9cd"
}

rule MalwareBazaar_unknown_061_df540e05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df540e050ac8f07b503203500b12839c7a9a0b0ef6dfc0c4d9ea62fcd4ce8ca9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:31:36"
  condition:
    hash.sha256(0, filesize) == "df540e050ac8f07b503203500b12839c7a9a0b0ef6dfc0c4d9ea62fcd4ce8ca9"
}

rule MalwareBazaar_unknown_062_9b5d20de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b5d20de3bc902c481465ec98d4ffd5c6656ea395a47858b31a320fb2675e754"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 01:25:24"
  condition:
    hash.sha256(0, filesize) == "9b5d20de3bc902c481465ec98d4ffd5c6656ea395a47858b31a320fb2675e754"
}

rule MalwareBazaar_unknown_063_5f3812aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412"
    family = "unknown"
    file_name = "5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412"
    file_type = "elf"
    first_seen = "2026-09-17 01:17:26"
  condition:
    hash.sha256(0, filesize) == "5f3812aa9b0d7bd239343b621fa625b7f9e81c64c9dc247b5560beb9b86ba412"
}

rule MalwareBazaar_Mozi_064_d97bb439
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522"
    family = "Mozi"
    file_name = "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522"
    file_type = "elf"
    first_seen = "2026-09-17 01:17:20"
  condition:
    hash.sha256(0, filesize) == "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522"
}

rule MalwareBazaar_Mirai_065_ae2c632f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104"
    family = "Mirai"
    file_name = "ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104"
    file_type = "elf"
    first_seen = "2026-09-17 01:17:13"
  condition:
    hash.sha256(0, filesize) == "ae2c632f0a5a54e197bef63cd95bd9b122a138ceae6d6751dd126c3ee92b5104"
}

rule MalwareBazaar_unknown_066_a7af6e22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7af6e228b27fb60dd2287c220f06b9a092ba2fc64d0bcafa65fbbc3a47e5a6d"
    family = "unknown"
    file_name = "update.mips"
    file_type = "elf"
    first_seen = "2026-09-17 01:16:56"
  condition:
    hash.sha256(0, filesize) == "a7af6e228b27fb60dd2287c220f06b9a092ba2fc64d0bcafa65fbbc3a47e5a6d"
}

rule MalwareBazaar_unknown_067_e012af05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e012af052ab3266d353194bf035e49f94523ca34f05ce7b2f13cffcae684f7fd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:36:19"
  condition:
    hash.sha256(0, filesize) == "e012af052ab3266d353194bf035e49f94523ca34f05ce7b2f13cffcae684f7fd"
}

rule MalwareBazaar_unknown_068_f5c0a557
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c0a557a1cd39beabca33ce63485d285f1180ef8d9e6dfcad5b65e5ff9c844c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:33:49"
  condition:
    hash.sha256(0, filesize) == "f5c0a557a1cd39beabca33ce63485d285f1180ef8d9e6dfcad5b65e5ff9c844c"
}

rule MalwareBazaar_unknown_069_31bc6b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31bc6b0c74347b3bd5446b52b4b1792d4f6c172fe100f87701b9deadf0bdaddb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:32:39"
  condition:
    hash.sha256(0, filesize) == "31bc6b0c74347b3bd5446b52b4b1792d4f6c172fe100f87701b9deadf0bdaddb"
}

rule MalwareBazaar_unknown_070_fe90a471
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe90a471cc5f82f86c5258602c77a7867a84c95afe788a50e57c5b8362991ab5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:31:47"
  condition:
    hash.sha256(0, filesize) == "fe90a471cc5f82f86c5258602c77a7867a84c95afe788a50e57c5b8362991ab5"
}

rule MalwareBazaar_unknown_071_e744b8e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e744b8e3d2df35b6c93078a93d6ee17f352ce1411975628191fae7627dfdd239"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:31:23"
  condition:
    hash.sha256(0, filesize) == "e744b8e3d2df35b6c93078a93d6ee17f352ce1411975628191fae7627dfdd239"
}

rule MalwareBazaar_unknown_072_1bd50b82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bd50b8202892d4dd885d18ba2e4eac4801a3eeef40d1c2b9915b7b109699e94"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:28:58"
  condition:
    hash.sha256(0, filesize) == "1bd50b8202892d4dd885d18ba2e4eac4801a3eeef40d1c2b9915b7b109699e94"
}

rule MalwareBazaar_unknown_073_eae16274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae16274ff967c4a27449dc663b2183bb5d447fbe2078ff0db0bc9dafdeb7bc0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:20:46"
  condition:
    hash.sha256(0, filesize) == "eae16274ff967c4a27449dc663b2183bb5d447fbe2078ff0db0bc9dafdeb7bc0"
}

rule MalwareBazaar_unknown_074_0b8038d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8038d60d3fd332fb04b310637a2035a6807ddb522a1ebfb19f238297285760"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:18:19"
  condition:
    hash.sha256(0, filesize) == "0b8038d60d3fd332fb04b310637a2035a6807ddb522a1ebfb19f238297285760"
}

rule MalwareBazaar_unknown_075_62c39f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01"
    family = "unknown"
    file_name = "62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01"
    file_type = "elf"
    first_seen = "2026-09-17 00:17:26"
  condition:
    hash.sha256(0, filesize) == "62c39f280b1dacaca00e4e9ac8fee25f6758d2db46ab1a85db85fd3139ad3e01"
}

rule MalwareBazaar_unknown_076_cb53ff3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90"
    family = "unknown"
    file_name = "cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90"
    file_type = "elf"
    first_seen = "2026-09-17 00:17:19"
  condition:
    hash.sha256(0, filesize) == "cb53ff3b92cbda05ed5e82ce29fa1ab45158fd4536b53cc97dc2d74b17de1b90"
}

rule MalwareBazaar_Mirai_077_2c8224b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd"
    family = "Mirai"
    file_name = "2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd"
    file_type = "elf"
    first_seen = "2026-09-17 00:17:13"
  condition:
    hash.sha256(0, filesize) == "2c8224b2f10417f3c90e876b051f97f6a11be654019abb64acce0279dded60dd"
}

rule MalwareBazaar_unknown_078_7934d8f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7934d8f55fd5d8f689a4568c3050246149dae29e1ceca7bc31dedcfdbdb96b3c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-17 00:15:45"
  condition:
    hash.sha256(0, filesize) == "7934d8f55fd5d8f689a4568c3050246149dae29e1ceca7bc31dedcfdbdb96b3c"
}

rule MalwareBazaar_unknown_079_7070c769
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045"
    family = "unknown"
    file_name = "7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045.bin"
    file_type = "unknown"
    first_seen = "2026-09-17 00:06:44"
  condition:
    hash.sha256(0, filesize) == "7070c769cd06c9956d8a9b3fbe5f322d1ed6a7da5269e74fc0a4d3fe012fc045"
}

rule MalwareBazaar_unknown_080_01637576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2"
    family = "unknown"
    file_name = "016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2.bin"
    file_type = "unknown"
    first_seen = "2026-09-17 00:06:27"
  condition:
    hash.sha256(0, filesize) == "016375769c3c8028456603a5e78a2305b4617304a001fcbdd2001330d135bef2"
}

rule MalwareBazaar_unknown_081_88cd0f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88cd0f5f6f0ed0780b450cc53f18136cb3f8245aef432e563ca30b6ec30bbfc6"
    family = "unknown"
    file_name = "python312-runtime-apphost.zip"
    file_type = "zip"
    first_seen = "2026-09-17 00:03:04"
  condition:
    hash.sha256(0, filesize) == "88cd0f5f6f0ed0780b450cc53f18136cb3f8245aef432e563ca30b6ec30bbfc6"
}

rule MalwareBazaar_unknown_082_1280ff5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1280ff5f2c4a59e8a9301d8e2eb7c2e9774ec6026a48905c52d23fb1974438bf"
    family = "unknown"
    file_name = "app.pyd"
    file_type = "exe"
    first_seen = "2026-09-17 00:02:50"
  condition:
    hash.sha256(0, filesize) == "1280ff5f2c4a59e8a9301d8e2eb7c2e9774ec6026a48905c52d23fb1974438bf"
}

rule MalwareBazaar_Mirai_083_64cfe4f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cfe4f7abbbd114c77ca589c96cf77a43ee1a03a4b45f55de8ddfc1a06a4546"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:45"
  condition:
    hash.sha256(0, filesize) == "64cfe4f7abbbd114c77ca589c96cf77a43ee1a03a4b45f55de8ddfc1a06a4546"
}

rule MalwareBazaar_Mirai_084_2936a273
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2936a273207cd8c6d4818417ce1cf6004a91a4b481641053f68231432560392a"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:43"
  condition:
    hash.sha256(0, filesize) == "2936a273207cd8c6d4818417ce1cf6004a91a4b481641053f68231432560392a"
}

rule MalwareBazaar_Mirai_085_451ee04f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451ee04f7f27631d0d184be98151e83401371ae347ca1ba81d8697973656684d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:41"
  condition:
    hash.sha256(0, filesize) == "451ee04f7f27631d0d184be98151e83401371ae347ca1ba81d8697973656684d"
}

rule MalwareBazaar_Mirai_086_bdeeb22e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdeeb22e0311ca8f724be3a46067cf868e48355d89c41ce8c511202dbfa83d34"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:40"
  condition:
    hash.sha256(0, filesize) == "bdeeb22e0311ca8f724be3a46067cf868e48355d89c41ce8c511202dbfa83d34"
}

rule MalwareBazaar_Mirai_087_6b357f5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b357f5c166c3297b75b804eb07d51141a4da4633a16dd28bfd42054c893950e"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-16 23:48:38"
  condition:
    hash.sha256(0, filesize) == "6b357f5c166c3297b75b804eb07d51141a4da4633a16dd28bfd42054c893950e"
}

rule MalwareBazaar_unknown_088_e58d5583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e58d5583cb71b8e3f3a95ef7cc9a0ba4fba76fa4ca03ebd7e8e5a91810f6250d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:42:01"
  condition:
    hash.sha256(0, filesize) == "e58d5583cb71b8e3f3a95ef7cc9a0ba4fba76fa4ca03ebd7e8e5a91810f6250d"
}

rule MalwareBazaar_CoinMiner_089_d45f4103
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45f4103caae9f2cf203a6cfbb1b0c075ab64208ff7c6af0b3e5b3232b02f91a"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:41:06"
  condition:
    hash.sha256(0, filesize) == "d45f4103caae9f2cf203a6cfbb1b0c075ab64208ff7c6af0b3e5b3232b02f91a"
}

rule MalwareBazaar_unknown_090_a0615903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a06159034f2e9d1db463a3a63349758145f88f7a70dbe16824bc46d0d49e397c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:37:12"
  condition:
    hash.sha256(0, filesize) == "a06159034f2e9d1db463a3a63349758145f88f7a70dbe16824bc46d0d49e397c"
}

rule MalwareBazaar_unknown_091_1e4e63f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e4e63f83a5871c8c94d804572f7455a5472fe73f102208e8a3029582769aa81"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:31:53"
  condition:
    hash.sha256(0, filesize) == "1e4e63f83a5871c8c94d804572f7455a5472fe73f102208e8a3029582769aa81"
}

rule MalwareBazaar_Mirai_092_02cc5e35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02cc5e354a59888caf2a700a7c7423bab396df16cd031994df046bd073fa2978"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-16 23:31:33"
  condition:
    hash.sha256(0, filesize) == "02cc5e354a59888caf2a700a7c7423bab396df16cd031994df046bd073fa2978"
}

rule MalwareBazaar_Mirai_093_b95e802e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95e802eb09c9e7aad64e142591d2e7b2bea5c8b751f31d82ac6d193bfd95d1b"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-16 23:31:32"
  condition:
    hash.sha256(0, filesize) == "b95e802eb09c9e7aad64e142591d2e7b2bea5c8b751f31d82ac6d193bfd95d1b"
}

rule MalwareBazaar_unknown_094_7443284a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7443284aa2c52b644026bf9d6913ac25c190e82af7cef6db5dd7909e0d9210ba"
    family = "unknown"
    file_name = "update.mips"
    file_type = "elf"
    first_seen = "2026-09-16 23:31:25"
  condition:
    hash.sha256(0, filesize) == "7443284aa2c52b644026bf9d6913ac25c190e82af7cef6db5dd7909e0d9210ba"
}

rule MalwareBazaar_unknown_095_ab7341a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab7341a28293c5607f3701879c00f4ca4f315611ff8fc0246f2401228742ee7d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 23:29:27"
  condition:
    hash.sha256(0, filesize) == "ab7341a28293c5607f3701879c00f4ca4f315611ff8fc0246f2401228742ee7d"
}

rule MalwareBazaar_Mirai_096_a98d913f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98d913fc773efa9a950bc11fcb170d602cb624963e5e3086c82cf6dc8b42c37"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-09-16 23:27:23"
  condition:
    hash.sha256(0, filesize) == "a98d913fc773efa9a950bc11fcb170d602cb624963e5e3086c82cf6dc8b42c37"
}

rule MalwareBazaar_JOMANGY_097_38670c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38670c27775aeb5d6f548e971fd22c6d10eb61a6e44f1003d8fd7c909c0799d4"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 23:23:13"
  condition:
    hash.sha256(0, filesize) == "38670c27775aeb5d6f548e971fd22c6d10eb61a6e44f1003d8fd7c909c0799d4"
}

rule MalwareBazaar_JOMANGY_098_28853653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28853653cfba4d9a93f25a90a91ab851e1c38d639a6b5e8078342325d334f529"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 23:23:12"
  condition:
    hash.sha256(0, filesize) == "28853653cfba4d9a93f25a90a91ab851e1c38d639a6b5e8078342325d334f529"
}

rule MalwareBazaar_unknown_099_64bf8990
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bf8990b84d3480b0f5585ec932d96d719e6e8e7285a0705cc8054cdbc46663"
    family = "unknown"
    file_name = "release-x64.exe"
    file_type = "exe"
    first_seen = "2026-09-16 23:18:21"
  condition:
    hash.sha256(0, filesize) == "64bf8990b84d3480b0f5585ec932d96d719e6e8e7285a0705cc8054cdbc46663"
}

rule MalwareBazaar_unknown_100_71ad71b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71ad71b4015e63291ea4fc8b6cab6260cf1198b36fb9767d4724df6f7f269689"
    family = "unknown"
    file_name = "main.exe"
    file_type = "exe"
    first_seen = "2026-09-16 23:18:13"
  condition:
    hash.sha256(0, filesize) == "71ad71b4015e63291ea4fc8b6cab6260cf1198b36fb9767d4724df6f7f269689"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

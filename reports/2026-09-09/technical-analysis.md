# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-09

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 621 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 621 |
| Unique family labels | 7 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 50 |
| Mirai | 41 |
| VShell | 4 |
| ConnectWise | 2 |
| ValleyRAT | 1 |
| NanoCore | 1 |
| SilentNet | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 40 |
| exe | 25 |
| sh | 11 |
| unknown | 9 |
| jar | 9 |
| zip | 2 |
| vbs | 2 |
| js | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `05619f43a3fc34d5`

| Field | Value |
|---|---|
| SHA-256 | `05619f43a3fc34d50709f784dcb7f7c47c88d0c32d5b6d8d0c0e720d68de1a81` |
| Family label | `unknown` |
| File name | `所得税の確定申告に係る納税通知書.zip` |
| File type | `zip` |
| First seen | `2026-09-09 04:33:13` |
| Reporter | `ppt_lol` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75115dd0ac51d507ace0dfe843ba659e` |
| SHA-1 | `436b22b0bfc2051bed6df0b4555dec003d977c87` |
| SHA-256 | `05619f43a3fc34d50709f784dcb7f7c47c88d0c32d5b6d8d0c0e720d68de1a81` |
| SHA3-384 | `59a4b2233b5d9d43d93d76b2fb3df066211f33ca8218767bb54e00fe56559b3fdcdd87ff92c26e7e3a6d4ee626e07a42` |
| TLSH | `T162A5332AEF6812A3B707D87F9A4BB06E5A270DC5CFD9096CDF186E5E1442FE49440E0D` |
| SSDEEP | `49152:mfSunvmoTtTNfLGhPcXkQUpJxYoBsXCJ7Rcl0zx:mhvPzDGhPc0QYxOC/zx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_05619f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05619f43a3fc34d50709f784dcb7f7c47c88d0c32d5b6d8d0c0e720d68de1a81"
    family = "unknown"
    file_name = "所得税の確定申告に係る納税通知書.zip"
    file_type = "zip"
    first_seen = "2026-09-09 04:33:13"
  condition:
    hash.sha256(0, filesize) == "05619f43a3fc34d50709f784dcb7f7c47c88d0c32d5b6d8d0c0e720d68de1a81"
}
```

### Sample 2: `f45af05d0c72ce31`

| Field | Value |
|---|---|
| SHA-256 | `f45af05d0c72ce3125c41cfd4b87b428f9466be5137ac41ce4daf84b12a06eeb` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-09 04:27:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de1b41efce47b995662f2b0158139174` |
| SHA-1 | `892bd93f458bfd96604c6b973f1581ec28ccf0bf` |
| SHA-256 | `f45af05d0c72ce3125c41cfd4b87b428f9466be5137ac41ce4daf84b12a06eeb` |
| SHA3-384 | `dc813051ef066b9cfb11b547df45cd066ecab507ac10ac78ca5443e9447edadca506363d0cfee3a59ba4f782ad0e6787` |
| TLSH | `T188C28D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACC618B1A` |
| SSDEEP | `768:Y8vCB+25j6es8RF9FYpMSUpi+20qUpi+20YQX:Y8l25Jjd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_f45af05d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f45af05d0c72ce3125c41cfd4b87b428f9466be5137ac41ce4daf84b12a06eeb"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-09 04:27:51"
  condition:
    hash.sha256(0, filesize) == "f45af05d0c72ce3125c41cfd4b87b428f9466be5137ac41ce4daf84b12a06eeb"
}
```

### Sample 3: `4c4543b1963b22fb`

| Field | Value |
|---|---|
| SHA-256 | `4c4543b1963b22fb4bdd039558c6f8ea913ada5c61f1b36637318804dec9f322` |
| Family label | `unknown` |
| File name | `.X0-lock_x86_64` |
| File type | `elf` |
| First seen | `2026-09-09 04:21:31` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce2965e0dde84edcae60ed7dded6d9ff` |
| SHA-1 | `34c828f172d67548569b2b00e5fa69dfe6c158c3` |
| SHA-256 | `4c4543b1963b22fb4bdd039558c6f8ea913ada5c61f1b36637318804dec9f322` |
| SHA3-384 | `840b60ce070e051e78f5d54978ed807cc00917135bfb3c14cdce6daf8bbf2f7a15a840ce914d50fea2c4d79ec704ae54` |
| TLSH | `T12226AE17B6A254FDC0E6C830838BD573AD35B8555221397B7684AB302E76F305F2EBA1` |
| SSDEEP | `98304:sgzgxMM+jACCVQJAQUb01vL9TWo16X22j8rRPR:jFZcZQJdPhTZ1trRPR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_4c4543b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c4543b1963b22fb4bdd039558c6f8ea913ada5c61f1b36637318804dec9f322"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-09 04:21:31"
  condition:
    hash.sha256(0, filesize) == "4c4543b1963b22fb4bdd039558c6f8ea913ada5c61f1b36637318804dec9f322"
}
```

### Sample 4: `7627323dc2af3b1e`

| Field | Value |
|---|---|
| SHA-256 | `7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a` |
| Family label | `VShell` |
| File name | `7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a.exe` |
| File type | `exe` |
| First seen | `2026-09-09 04:08:42` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a8839a22124ec0ac5dd1a58c2272a37` |
| SHA-1 | `2129ce92b58a268553970920f268da5414ee44bb` |
| SHA-256 | `7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a` |
| SHA3-384 | `ba5476f132f7227dae37d1fa25a6eb1aed8a364ac676d7be0799bd0096072074993ce754f0fb9524c820c162d37d9152` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1C471B541A0545AF2D94CE37F8487B895FD4FB248A2C80B0F0398981A2F710BBB0DDA13` |
| SSDEEP | `48:6IZUBQYxZul2EywS6De3njk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6De3j++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_004_7627323d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a"
    family = "VShell"
    file_name = "7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a.exe"
    file_type = "exe"
    first_seen = "2026-09-09 04:08:42"
  condition:
    hash.sha256(0, filesize) == "7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a"
}
```

### Sample 5: `4dafdbb610afca67`

| Field | Value |
|---|---|
| SHA-256 | `4dafdbb610afca675acd37d4df766ebf84ab0b903ce270696218a9a9b56f2c13` |
| Family label | `unknown` |
| File name | `EP-342152026_ORDER_QOUTATION_FORMS.js` |
| File type | `js` |
| First seen | `2026-09-09 03:56:36` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8938b53f514780745b5729268815e93` |
| SHA-1 | `7822e4d8e508fd8244b8985b628f580c8626cc2d` |
| SHA-256 | `4dafdbb610afca675acd37d4df766ebf84ab0b903ce270696218a9a9b56f2c13` |
| SHA3-384 | `bd174de443551b370f696e48c4a2345001bc291b96f34b5f6343c772124ca7966a514b8f55c3a5a3081a060392448086` |
| TLSH | `T1EDE50BF2738B4B062B15F377AA4E0C580F46E082D6879ED070DE4AD4175B94D3EE49AE` |
| SSDEEP | `24576:nIkJYApwCazH9XwmxMGlWqC5s02Tfr0obO0kqHku:IsYApXazNPxz/Clv0LHp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_4dafdbb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dafdbb610afca675acd37d4df766ebf84ab0b903ce270696218a9a9b56f2c13"
    family = "unknown"
    file_name = "EP-342152026_ORDER_QOUTATION_FORMS.js"
    file_type = "js"
    first_seen = "2026-09-09 03:56:36"
  condition:
    hash.sha256(0, filesize) == "4dafdbb610afca675acd37d4df766ebf84ab0b903ce270696218a9a9b56f2c13"
}
```

### Sample 6: `35d2e3cc6fe69e46`

| Field | Value |
|---|---|
| SHA-256 | `35d2e3cc6fe69e460a6ec4ea1a406582581bcd17be4807cafe49df8e779e9d99` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-09 03:39:26` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6573806384cd4b06533eb2b21d78a12b` |
| SHA-256 | `35d2e3cc6fe69e460a6ec4ea1a406582581bcd17be4807cafe49df8e779e9d99` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_35d2e3cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d2e3cc6fe69e460a6ec4ea1a406582581bcd17be4807cafe49df8e779e9d99"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-09 03:39:26"
  condition:
    hash.sha256(0, filesize) == "35d2e3cc6fe69e460a6ec4ea1a406582581bcd17be4807cafe49df8e779e9d99"
}
```

### Sample 7: `50079751c8f42b07`

| Field | Value |
|---|---|
| SHA-256 | `50079751c8f42b0730494ff5482b4684eb62b560be7b1dc4b9c6f27e069a4e95` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-09 03:37:54` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b9a9521010c6ccf568a0ddc9d59832e` |
| SHA-256 | `50079751c8f42b0730494ff5482b4684eb62b560be7b1dc4b9c6f27e069a4e95` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_50079751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50079751c8f42b0730494ff5482b4684eb62b560be7b1dc4b9c6f27e069a4e95"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-09 03:37:54"
  condition:
    hash.sha256(0, filesize) == "50079751c8f42b0730494ff5482b4684eb62b560be7b1dc4b9c6f27e069a4e95"
}
```

### Sample 8: `481ab3406ddfd6b9`

| Field | Value |
|---|---|
| SHA-256 | `481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57` |
| Family label | `Mirai` |
| File name | `481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57.elf` |
| File type | `elf` |
| First seen | `2026-09-09 03:33:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce3f178fc13438b4c45d84bf34b0a3b6` |
| SHA-1 | `bc2153bd86aee7d6c93fbb56bf25f43a9d0a3339` |
| SHA-256 | `481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57` |
| SHA3-384 | `5ab650c503325b7cf0d862ddfa2a3704a3d39db720bd767bf241475b4f7cb1989ccee53b92338feda390efe11e6b7531` |
| TLSH | `T1EFA32C80FD458767C3C227B7F78E479D3B355A649BDB331165386EF42B81B982E29220` |
| TELFHASH | `t17311239221ff89282bf24928ac7c47b11591211323917e70ef1ec5d44437046f965d9f` |
| SSDEEP | `3072:U9d1uE0Ylk0t58SU8toJ2eM5RUyZB0BmQwiQmvvhMXWyA:6hU8CpSRUyj4mQwiQmv5MXWyA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_481ab340
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57"
    family = "Mirai"
    file_name = "481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57.elf"
    file_type = "elf"
    first_seen = "2026-09-09 03:33:45"
  condition:
    hash.sha256(0, filesize) == "481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57"
}
```

### Sample 9: `76361341b7f86862`

| Field | Value |
|---|---|
| SHA-256 | `76361341b7f86862fae2235d1f67de4c0d3f9ec2ba108328d40b18f7800bc591` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-09 03:27:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22816350d9e0b7ea15e3c204b49d100c` |
| SHA-1 | `d1bad1c53cf6af583eb460bbdc7274cdde9561ff` |
| SHA-256 | `76361341b7f86862fae2235d1f67de4c0d3f9ec2ba108328d40b18f7800bc591` |
| SHA3-384 | `07b874beb3473f8783abb9b5681901f5db50266c8212ee661502411fd27aae155c759eee07bdcb5c83fd694258e29c5e` |
| TLSH | `T112C27C966A867C44BDC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15F9CD618B1A` |
| SSDEEP | `768:YXc8vCB+25j6es8RPK9FYpMSUpi+20qUpi+20YQX:wc8l25JP8d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_76361341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76361341b7f86862fae2235d1f67de4c0d3f9ec2ba108328d40b18f7800bc591"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-09 03:27:28"
  condition:
    hash.sha256(0, filesize) == "76361341b7f86862fae2235d1f67de4c0d3f9ec2ba108328d40b18f7800bc591"
}
```

### Sample 10: `410fe1699749582a`

| Field | Value |
|---|---|
| SHA-256 | `410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62` |
| Family label | `Mirai` |
| File name | `410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62.elf` |
| File type | `elf` |
| First seen | `2026-09-09 03:23:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e0d8a526213432bf0952bdb08a569a1` |
| SHA-1 | `757d51f7ffcacaaee4bddc7998e30290d623c1e7` |
| SHA-256 | `410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62` |
| SHA3-384 | `7008f65a1c529b57477b067b9d8c10797be722fde47d603a8cff92032488e890af472af399a5878e8f095e26b9ef0d47` |
| TLSH | `T18DC32901E5908767C2D2137AF79F429D37336F68979B33219A24BBF42B8179D1E39221` |
| TELFHASH | `t1ad212d5262fe8a286bf35924ec7c43b115a12a2362857e70bf1ec5c4443b047b865daf` |
| SSDEEP | `3072:zcP+wadgzyj+AmM2aTXOwszFibFl3yQRb6EPvqUYmcQY47aGgp:zD+AH2aTGibD3yrmqUYmcQY4+Ggp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_410fe169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62"
    family = "Mirai"
    file_name = "410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62.elf"
    file_type = "elf"
    first_seen = "2026-09-09 03:23:44"
  condition:
    hash.sha256(0, filesize) == "410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62"
}
```

### Sample 11: `a5af2c9eead719aa`

| Field | Value |
|---|---|
| SHA-256 | `a5af2c9eead719aae42ef1fd7a8e78b3a1caebd7f053e3bb34cd74a1e5c470ef` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-09 03:20:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc6f7df42ad2dc7f8664836e62f38003` |
| SHA-1 | `144b53a1387029cb2a583cc49240218f093dab13` |
| SHA-256 | `a5af2c9eead719aae42ef1fd7a8e78b3a1caebd7f053e3bb34cd74a1e5c470ef` |
| SHA3-384 | `48046d151d6f4503bc5d7e94c06b264ba20666f45f0844f61bc39f57b3c3429fa2088c4fec501a6661367dada4fcc5f2` |
| TLSH | `T18F236C6516857C15AA99C4371C7E2F0CBDAD43E6320452DE7FCE3CF28C4AA9DA20971D` |
| SSDEEP | `768:4csr0a1ldXal9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:2h9cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_a5af2c9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5af2c9eead719aae42ef1fd7a8e78b3a1caebd7f053e3bb34cd74a1e5c470ef"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-09 03:20:00"
  condition:
    hash.sha256(0, filesize) == "a5af2c9eead719aae42ef1fd7a8e78b3a1caebd7f053e3bb34cd74a1e5c470ef"
}
```

### Sample 12: `dbf8a577d037022a`

| Field | Value |
|---|---|
| SHA-256 | `dbf8a577d037022a5c8834874be21590b399b0dc5e5103241b3d34d723d05186` |
| Family label | `Mirai` |
| File name | `telnetd` |
| File type | `elf` |
| First seen | `2026-09-09 03:19:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0566d137b0d610df1e5e8db6741d4358` |
| SHA-1 | `1479faf30c193950f4666f25e0f64c75b8dccc5a` |
| SHA-256 | `dbf8a577d037022a5c8834874be21590b399b0dc5e5103241b3d34d723d05186` |
| SHA3-384 | `2351f5847ab99df1b3cdd97157a022bf2383b8380e20a1066640df415dffa3cd55bcac1dd6c9e9fe4cc6e031c25d9781` |
| TLSH | `T1E3B33B41FD408767C2D227B6F78E479D3B365A6497DB331169397EB42BC1B882E39220` |
| TELFHASH | `t17311239221ff89282bf24928ac7c47b11591211323917e70ef1ec5d44437046f965d9f` |
| SSDEEP | `3072:Xqd1uE0YlkRt5RiUlaYS6KP5Vyuzw5dm7ZTQOh21JXwQA:RiUlGFRVyu4m7ZTQOhMJXwQA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_dbf8a577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf8a577d037022a5c8834874be21590b399b0dc5e5103241b3d34d723d05186"
    family = "Mirai"
    file_name = "telnetd"
    file_type = "elf"
    first_seen = "2026-09-09 03:19:59"
  condition:
    hash.sha256(0, filesize) == "dbf8a577d037022a5c8834874be21590b399b0dc5e5103241b3d34d723d05186"
}
```

### Sample 13: `a64f579aaddbfe0f`

| Field | Value |
|---|---|
| SHA-256 | `a64f579aaddbfe0f05cf6fdbd528ed98e35ef54d2c9869b35fdd800ef559420b` |
| Family label | `unknown` |
| File name | `youtube-music-free.exe` |
| File type | `exe` |
| First seen | `2026-09-09 03:16:08` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `503f6644d405ea64eeb00eb9a29767a1` |
| SHA-1 | `2a279952b72ed00104981cd34ff04a900eafce3b` |
| SHA-256 | `a64f579aaddbfe0f05cf6fdbd528ed98e35ef54d2c9869b35fdd800ef559420b` |
| SHA3-384 | `b3eaffd943eb1f47a23ac90673afef1c641c15525bd4e1485476e8cecb4642745a527d592c7bcf0c2fdf5f960d297e96` |
| IMPHASH | `0578002c9fc8279f752de56cfee7a485` |
| TLSH | `T18F459CD175528039C69603724A7C7FBD117DADE81BA1C9CFAFC8362CD6331C26A3664A` |
| SSDEEP | `24576:qH8HmJaIgNYsfbDJvioYMhBt5svWNGFpZC9dYh:4pq/5svCGRCHYh` |
| ICON-DHASH | `e0d8f8c8c9fcf8e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_a64f579a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a64f579aaddbfe0f05cf6fdbd528ed98e35ef54d2c9869b35fdd800ef559420b"
    family = "unknown"
    file_name = "youtube-music-free.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:16:08"
  condition:
    hash.sha256(0, filesize) == "a64f579aaddbfe0f05cf6fdbd528ed98e35ef54d2c9869b35fdd800ef559420b"
}
```

### Sample 14: `6e846994c31e4877`

| Field | Value |
|---|---|
| SHA-256 | `6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421` |
| Family label | `unknown` |
| File name | `6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421.bin` |
| File type | `unknown` |
| First seen | `2026-09-09 03:08:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fdba616e7ee0136cb46394ad8b5673c` |
| SHA-256 | `6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_6e846994
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421"
    family = "unknown"
    file_name = "6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421.bin"
    file_type = "unknown"
    first_seen = "2026-09-09 03:08:43"
  condition:
    hash.sha256(0, filesize) == "6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421"
}
```

### Sample 15: `d13752d409ddb0e6`

| Field | Value |
|---|---|
| SHA-256 | `d13752d409ddb0e6f87bd72259a343f7a70bd13c30b03943019123a96e4a2070` |
| Family label | `ValleyRAT` |
| File name | `win-Bundle x643014.exe` |
| File type | `exe` |
| First seen | `2026-09-09 03:03:20` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ab97203e3e3d4d5d24e8c6ab6bc095b` |
| SHA-1 | `383430f170ef403df9a23269f56f040a2ec8cfe5` |
| SHA-256 | `d13752d409ddb0e6f87bd72259a343f7a70bd13c30b03943019123a96e4a2070` |
| SHA3-384 | `b57d9f3da53cb48cf44004ba3bfeaf436727309c72c9d2c0efa51c576e8da2c19a9f54f58e7290328c3d9c0125a1251c` |
| IMPHASH | `57e98d9a5a72c8d7ad8fb7a6a58b3daf` |
| TLSH | `T10B17336C3D65CCDAE2B547B0479E24521FAB8C4F05025DDBE385FE2A9EB27A37049B10` |
| SSDEEP | `393216:TOsMYynxwj7figtUj8LF31j+tnF2zudKKtwmS0gUOvxzSyna2OP9I:TOuyxG26LF30F212w+2xzna2OVI` |
| ICON-DHASH | `c4ccb392f1f192cc` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_015_d13752d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d13752d409ddb0e6f87bd72259a343f7a70bd13c30b03943019123a96e4a2070"
    family = "ValleyRAT"
    file_name = "win-Bundle x643014.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:03:20"
  condition:
    hash.sha256(0, filesize) == "d13752d409ddb0e6f87bd72259a343f7a70bd13c30b03943019123a96e4a2070"
}
```

### Sample 16: `66c9668d460f0d3f`

| Field | Value |
|---|---|
| SHA-256 | `66c9668d460f0d3f71fb0ed42b895d53f90f4415ea9493e1dd2695cb505be9a6` |
| Family label | `unknown` |
| File name | `instell_s2.0.08.exe` |
| File type | `exe` |
| First seen | `2026-09-09 03:02:05` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afb33bc91f6cdf5cd4dea233defdbf6e` |
| SHA-1 | `104c7ee356b841084b3d6085babd2bb5879fd969` |
| SHA-256 | `66c9668d460f0d3f71fb0ed42b895d53f90f4415ea9493e1dd2695cb505be9a6` |
| SHA3-384 | `024f3263e293314f0b432a49a6e75824d469161f0054f064533871ada375ce3fba2d0a9b79188dcee9cb2d409a12bfc3` |
| IMPHASH | `ce08ab0a87007f1423c570fdfcd13219` |
| TLSH | `T1BE777012B7018DDFF066A234689B8F61E332D8B106B1937723B1675D1FEE38C4EA6564` |
| SSDEEP | `98304:2+dP6pfrf0qBvdAmx6bc4a+4Z7eSv5GdCdAmQp:2Y6VsqIuH6S0dCdAme` |
| ICON-DHASH | `f0809296969280f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_66c9668d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66c9668d460f0d3f71fb0ed42b895d53f90f4415ea9493e1dd2695cb505be9a6"
    family = "unknown"
    file_name = "instell_s2.0.08.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:02:05"
  condition:
    hash.sha256(0, filesize) == "66c9668d460f0d3f71fb0ed42b895d53f90f4415ea9493e1dd2695cb505be9a6"
}
```

### Sample 17: `db9ce8f0eed01514`

| Field | Value |
|---|---|
| SHA-256 | `db9ce8f0eed015147b99abe421137da2be91f6496edf937b934c2b4123f0fd4f` |
| Family label | `unknown` |
| File name | `instell_s2.0.07.exe` |
| File type | `exe` |
| First seen | `2026-09-09 03:00:49` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `774616bf1d36bcc134257e31cd5f9ffc` |
| SHA-1 | `40ec018d94e13480dc84499452932bee76b16c74` |
| SHA-256 | `db9ce8f0eed015147b99abe421137da2be91f6496edf937b934c2b4123f0fd4f` |
| SHA3-384 | `dacddb41947c266c338aee11e84b43e1c03718ce6f0e1f99f70f95f7a32ee833618ff1455e73d1e658fb89ce24abc261` |
| IMPHASH | `ce08ab0a87007f1423c570fdfcd13219` |
| TLSH | `T1A3777012B7018DDFF066A234689B8F61E332D8B106B1937723B1675D1FEE38C4EA6564` |
| SSDEEP | `98304:v+dP6pfrf0qBvdAmx6bc4a+4Z7eSv5GdCdAmQf:vY6VsqIuH6S0dCdAmk` |
| ICON-DHASH | `f0809296969280f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_db9ce8f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db9ce8f0eed015147b99abe421137da2be91f6496edf937b934c2b4123f0fd4f"
    family = "unknown"
    file_name = "instell_s2.0.07.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:00:49"
  condition:
    hash.sha256(0, filesize) == "db9ce8f0eed015147b99abe421137da2be91f6496edf937b934c2b4123f0fd4f"
}
```

### Sample 18: `036fff70e9d3305e`

| Field | Value |
|---|---|
| SHA-256 | `036fff70e9d3305ecb0234e79d3ae373aa348ba0cf30d5526bcb13d2f51da0f7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-09 02:45:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0de073777b10edd83ce98b2934cde708` |
| SHA-1 | `55458a70a866c20cbed364a1402bdfa0e6bed1cd` |
| SHA-256 | `036fff70e9d3305ecb0234e79d3ae373aa348ba0cf30d5526bcb13d2f51da0f7` |
| SHA3-384 | `6b8cdaf7e0670b3089fb4b55a7b87e76e9f628a7c74b0509c0a853fd8a52cc2de7e32294dadb60e7f6a7829c2310c0d4` |
| TLSH | `T1AB236C6516857C14AA99C8365D7F2F0CBDAD43E6314492EE7FCA3CF28C4A6AC920861D` |
| SSDEEP | `768:Ir9NyXsZztCc9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:WHusZ8cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_036fff70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "036fff70e9d3305ecb0234e79d3ae373aa348ba0cf30d5526bcb13d2f51da0f7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-09 02:45:59"
  condition:
    hash.sha256(0, filesize) == "036fff70e9d3305ecb0234e79d3ae373aa348ba0cf30d5526bcb13d2f51da0f7"
}
```

### Sample 19: `2471a6c8da3933f1`

| Field | Value |
|---|---|
| SHA-256 | `2471a6c8da3933f1d8ba41a136fa0ca185801dfd26f73d2f8791449007153444` |
| Family label | `NanoCore` |
| File name | `5CDD5FA5921EA6D54EBDE06166D1AD9A.exe` |
| File type | `exe` |
| First seen | `2026-09-09 02:45:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cdd5fa5921ea6d54ebde06166d1ad9a` |
| SHA-1 | `8f06edf96f194a0818a2da85e631af2fced7d383` |
| SHA-256 | `2471a6c8da3933f1d8ba41a136fa0ca185801dfd26f73d2f8791449007153444` |
| SHA3-384 | `f44bd9964bdaeacf510983c12d2acd79c9e67369fdc43730d185938b85ab5232578dbe204005969a10c5ef641c6f2565` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E514BF2577A94A2FE2DF86B8B12251139379C2E799C3F3EE28E455B24F163E106071D3` |
| SSDEEP | `3072:wzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HI9pVWLjxKXC0CSlMBjJtS9v3v:wLV6Bta6dtJmakIM5UWvUo4MBNti/` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_019_2471a6c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2471a6c8da3933f1d8ba41a136fa0ca185801dfd26f73d2f8791449007153444"
    family = "NanoCore"
    file_name = "5CDD5FA5921EA6D54EBDE06166D1AD9A.exe"
    file_type = "exe"
    first_seen = "2026-09-09 02:45:06"
  condition:
    hash.sha256(0, filesize) == "2471a6c8da3933f1d8ba41a136fa0ca185801dfd26f73d2f8791449007153444"
}
```

### Sample 20: `35664b1b0720aaf3`

| Field | Value |
|---|---|
| SHA-256 | `35664b1b0720aaf383086d2de50e91dbd7fa83f89b8b0dda7d5c1c03ffccc842` |
| Family label | `Mirai` |
| File name | `ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4` |
| File type | `elf` |
| First seen | `2026-09-09 02:40:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e27fa4fb576da50bbfe15a91e36198b` |
| SHA-1 | `6775cbcbfc020bf073e0d747d2e70b6519fb8d61` |
| SHA-256 | `35664b1b0720aaf383086d2de50e91dbd7fa83f89b8b0dda7d5c1c03ffccc842` |
| SHA3-384 | `260047d5ae2272e70c9c104300dc5bfd91d9f2400061ac3aa6a9ed02b061f4ed48fa28de3c6f6c0fc6750b56b8b666e5` |
| TLSH | `T10283B44D6F319F7DFBA8C73857B79A506608338A22E1D485D1ACEB060E6024E741FFA5` |
| TELFHASH | `t1d801c96c8eb423e49a368d5a046defa6e1b030da07226c274f15a96caabdc415e05c0d` |
| SSDEEP | `1536:NYxbiIEXLbY+rWU87fvZH0vKJJ56BbFNl1LGKjMiXzG+8:N0bY7lmZH0iL5iNl5GKjVXz38` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_35664b1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35664b1b0720aaf383086d2de50e91dbd7fa83f89b8b0dda7d5c1c03ffccc842"
    family = "Mirai"
    file_name = "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
    file_type = "elf"
    first_seen = "2026-09-09 02:40:30"
  condition:
    hash.sha256(0, filesize) == "35664b1b0720aaf383086d2de50e91dbd7fa83f89b8b0dda7d5c1c03ffccc842"
}
```

### Sample 21: `b18df0c8e3b445e4`

| Field | Value |
|---|---|
| SHA-256 | `b18df0c8e3b445e4f6581b354f0de6fc47b060834ea4867d32524f2e4032eefc` |
| Family label | `Mirai` |
| File name | `bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae` |
| File type | `elf` |
| First seen | `2026-09-09 02:40:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5307f145e440c2e3129f3f4cee13099` |
| SHA-1 | `c711a253f8d95b2065c51cf9069d6c27fce0cd7b` |
| SHA-256 | `b18df0c8e3b445e4f6581b354f0de6fc47b060834ea4867d32524f2e4032eefc` |
| SHA3-384 | `bcbc134df2b6f02ecab5616f4bed3ee6ad086404f0f45c3d5925ccbe113345153822214df38c8c0ba13da0556e4a0fbe` |
| TLSH | `T18B5339C4E2C3E8FAE810087D317AAF729E73F13EB135D99BD3D959639505A02E10625D` |
| TELFHASH | `t13a11c2fa5aba1cf4b7d0a850430e5d9609ae753f29203bb04672c81033bfd8290b8c3d` |
| SSDEEP | `1536:0UEMAWwPQk16qHTWKRmyaSkDu4eFOVgr:0UEMAWwr16qHTWKRmyaSmu4aOgr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_b18df0c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b18df0c8e3b445e4f6581b354f0de6fc47b060834ea4867d32524f2e4032eefc"
    family = "Mirai"
    file_name = "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
    file_type = "elf"
    first_seen = "2026-09-09 02:40:28"
  condition:
    hash.sha256(0, filesize) == "b18df0c8e3b445e4f6581b354f0de6fc47b060834ea4867d32524f2e4032eefc"
}
```

### Sample 22: `db2dfc1e627fb90b`

| Field | Value |
|---|---|
| SHA-256 | `db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25` |
| Family label | `unknown` |
| File name | `db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25` |
| File type | `unknown` |
| First seen | `2026-09-09 02:40:01` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65f6781c1fd861446ef37c2b9c51364c` |
| SHA-256 | `db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_db2dfc1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25"
    family = "unknown"
    file_name = "db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25"
    file_type = "unknown"
    first_seen = "2026-09-09 02:40:01"
  condition:
    hash.sha256(0, filesize) == "db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25"
}
```

### Sample 23: `ecee64f2446c402d`

| Field | Value |
|---|---|
| SHA-256 | `ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4` |
| Family label | `Mirai` |
| File name | `ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4` |
| File type | `elf` |
| First seen | `2026-09-09 02:39:59` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7f19e1854be867357dd8c63f0a3e6c5` |
| SHA-1 | `8b99ea57428eecdae169a9f1213e6265ea5fb789` |
| SHA-256 | `ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4` |
| SHA3-384 | `d45bf72fbc2b2eeeb01fde59546a30a70cc254f5a9f7dac83bbf346e07a6b678c85d3ef79ec3dc0a0ddd784323a76a0c` |
| TLSH | `T102D2E0B91A0A46CEDDAEC8FAC3A413A019660E126903FC4BB4ADD7475B5B5C0B107ADC` |
| SSDEEP | `768:yxMWBhAHuLegF1aF4NscfOl8liVQJgGlzDpbuR1JR:yxdBGuLea19acfjliyVJuL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_ecee64f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
    family = "Mirai"
    file_name = "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
    file_type = "elf"
    first_seen = "2026-09-09 02:39:59"
  condition:
    hash.sha256(0, filesize) == "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
}
```

### Sample 24: `bdaf3c99c0dc9f4a`

| Field | Value |
|---|---|
| SHA-256 | `bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae` |
| Family label | `Mirai` |
| File name | `bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae` |
| File type | `elf` |
| First seen | `2026-09-09 02:39:56` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd029fd1b0312ec933cf0eb0e44b946b` |
| SHA-1 | `33d4a702b2a120b461498de8eb0c46e78968b5b7` |
| SHA-256 | `bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae` |
| SHA3-384 | `d7a91c8d4abe38db8fc13f0939ce8f15a33f5e3679ce205193af9290c507f979bc39df56af9c710eed011f856d0c8b1c` |
| TLSH | `T186C2E1F53E777A9BEF2500383499CE329274F022D79FA613A241820921171BDBB715ED` |
| SSDEEP | `768:HMwoDZLFbBy6HQHRYfeAxdd8zsKkVTJpN0NG:HolcYfe6Kzy9pqw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_bdaf3c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
    family = "Mirai"
    file_name = "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
    file_type = "elf"
    first_seen = "2026-09-09 02:39:56"
  condition:
    hash.sha256(0, filesize) == "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
}
```

### Sample 25: `a0983541675c369c`

| Field | Value |
|---|---|
| SHA-256 | `a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a` |
| Family label | `Mirai` |
| File name | `a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a` |
| File type | `sh` |
| First seen | `2026-09-09 02:39:54` |
| Reporter | `c2hunter` |
| Tags | `Mirai, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fa418203e79c5412eccb674d9ff05c3` |
| SHA-1 | `0399137e13fb8bfb403b005e3363ba75752b7f46` |
| SHA-256 | `a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a` |
| SHA3-384 | `c9814b69cbbb2cd30e90ccb395fd217307b9697b56f15e915e30bef3297f854307322ec633fd6f4d60be1bd9cf4ace4a` |
| TLSH | `T14A516D95B3424831BFF59E9EB5F448147180E0A1EA84AE05D9FC7AF98A4DF0C26DC653` |
| SSDEEP | `48:vuVbqlqrsFCgpZJo5VQLMlJ78Xk3E0uau7R:v0mkIQO6aLiY03E/VN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_a0983541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a"
    family = "Mirai"
    file_name = "a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a"
    file_type = "sh"
    first_seen = "2026-09-09 02:39:54"
  condition:
    hash.sha256(0, filesize) == "a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a"
}
```

### Sample 26: `b7ed37d1f689a830`

| Field | Value |
|---|---|
| SHA-256 | `b7ed37d1f689a8302fecfb64ef4bc8828603d093926996965faca45e1ae869a8` |
| Family label | `Mirai` |
| File name | `1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6` |
| File type | `elf` |
| First seen | `2026-09-09 02:38:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b61dfd04e206e7dced233b9a931ccc6` |
| SHA-1 | `7e9343dd09123ee39d3bf0c0bc6670141f7ae780` |
| SHA-256 | `b7ed37d1f689a8302fecfb64ef4bc8828603d093926996965faca45e1ae869a8` |
| SHA3-384 | `d38b20558fc0161140586bbe6a4579e5707b0195f4f539d9b232bbb6a39497bb940557180140bc010f0c986626d35b91` |
| TLSH | `T183E33B85EA408A13C0D61776FAAF41493322DB55E3DB73079D189FF43FC6A9E0E26606` |
| TELFHASH | `t114211471173596256e60ce9c99eda771122887131389ff33df3584eca50909ee63ac4f` |
| SSDEEP | `3072:sqlhEFZBB9qPoLmpMguHcUlVUHalw7WguH0vsfC0XxmjX5Xa/NOL9eXgIncdVo2J:sqlhEFZBTqPoLmpMguHcUlVUHalw7Wg5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_b7ed37d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7ed37d1f689a8302fecfb64ef4bc8828603d093926996965faca45e1ae869a8"
    family = "Mirai"
    file_name = "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
    file_type = "elf"
    first_seen = "2026-09-09 02:38:16"
  condition:
    hash.sha256(0, filesize) == "b7ed37d1f689a8302fecfb64ef4bc8828603d093926996965faca45e1ae869a8"
}
```

### Sample 27: `a8655c0314ffb232`

| Field | Value |
|---|---|
| SHA-256 | `a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634` |
| Family label | `Mirai` |
| File name | `a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634` |
| File type | `elf` |
| First seen | `2026-09-09 02:37:47` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `669e7f6a34f03f9be2e67e17245878b3` |
| SHA-1 | `bf377a5d9f88ef24f95d2ef0b850a4b0bd1e1e3d` |
| SHA-256 | `a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634` |
| SHA3-384 | `4ad8823f0080f5eaae735595ac5eb0dface8257753f36ba81a63c8b1597f0de21bea22acffad1e439f545731f2e6bbc2` |
| TLSH | `T1BA33026227AE2AD291B05777FC33BC16669C17F95C6730993CF05A1977C48024EF2686` |
| SSDEEP | `1536:s9O/ZMAXIxNUk0VzL9O+LcPqF1aBexo4opKZbU:s9O/ZNKyNL9O+LGqFUFr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_a8655c03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634"
    family = "Mirai"
    file_name = "a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634"
    file_type = "elf"
    first_seen = "2026-09-09 02:37:47"
  condition:
    hash.sha256(0, filesize) == "a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634"
}
```

### Sample 28: `1002269048f76268`

| Field | Value |
|---|---|
| SHA-256 | `1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6` |
| Family label | `Mirai` |
| File name | `1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6` |
| File type | `elf` |
| First seen | `2026-09-09 02:37:35` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ea727b781d6fae2e3970102ea07537a` |
| SHA-1 | `6d78fb1af0952923320af6c4e96dced2a04841e2` |
| SHA-256 | `1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6` |
| SHA3-384 | `1c212c76948ad0d564d8a48c10655520ec4f364c8d89f95420ea8f0d403309b0a063288fc958611ecb27b350e3508369` |
| TLSH | `T1B133026227AE2AD291B05777FC33BC16669C17F95C6730993CF05A1977C48024EF2686` |
| SSDEEP | `1536:s9O/ZMAXIxNUk0VzL9O+LcPqF1aBexo4opKZbq:s9O/ZNKyNL9O+LGqFUF7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_10022690
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
    family = "Mirai"
    file_name = "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
    file_type = "elf"
    first_seen = "2026-09-09 02:37:35"
  condition:
    hash.sha256(0, filesize) == "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
}
```

### Sample 29: `9e8d5a90140383c4`

| Field | Value |
|---|---|
| SHA-256 | `9e8d5a90140383c459626e04b5e44288f90b6952da0cd10bb15d621f7093d35c` |
| Family label | `unknown` |
| File name | `Havnelbene.vbs` |
| File type | `vbs` |
| First seen | `2026-09-09 02:32:31` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb3832f242f5a31a119de3430ecb4e59` |
| SHA-1 | `40a3e6b8445ae76bcbe600dc8a44c95f5edb284d` |
| SHA-256 | `9e8d5a90140383c459626e04b5e44288f90b6952da0cd10bb15d621f7093d35c` |
| SHA3-384 | `56486471c293e77607c159e8d3d76d4676e4d39e92bcadb534032ed9b384bf8d002b8671c8d0c7b456ebd8e7e8a8e397` |
| TLSH | `T108C229AAAF3423624D4F27EFE8484C6585A4412508230CB17FB9735E2E45B9CF7BE15B` |
| SSDEEP | `768:zt0SQSmJqeIUO3mD8HiUjD+cDzSrlSo2UDsdLw3tBtTi:VmoAsmD8CUjDXzW0oXDssbtTi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_9e8d5a90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e8d5a90140383c459626e04b5e44288f90b6952da0cd10bb15d621f7093d35c"
    family = "unknown"
    file_name = "Havnelbene.vbs"
    file_type = "vbs"
    first_seen = "2026-09-09 02:32:31"
  condition:
    hash.sha256(0, filesize) == "9e8d5a90140383c459626e04b5e44288f90b6952da0cd10bb15d621f7093d35c"
}
```

### Sample 30: `6be8c092507dc1e7`

| Field | Value |
|---|---|
| SHA-256 | `6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91` |
| Family label | `VShell` |
| File name | `6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91.exe` |
| File type | `exe` |
| First seen | `2026-09-09 02:14:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b227ef0695eef8e01bd58d697fdeb500` |
| SHA-1 | `d056d36479d47b786bf92fedf1017f03d3c95219` |
| SHA-256 | `6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91` |
| SHA3-384 | `bdcd172c066c8ebd8e0f624b566423ee8f994fcb12965278e72955504c6df2dd109681cf35fd30c0e453520895f0a367` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T12991A5C5F75BE6B2EC1C07F500A3B9A8C4682E14827C9B564FE16F0C3C111AA3C2DA12` |
| SSDEEP | `48:6I7lwe7qz08SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1y091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_030_6be8c092
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91"
    family = "VShell"
    file_name = "6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91.exe"
    file_type = "exe"
    first_seen = "2026-09-09 02:14:11"
  condition:
    hash.sha256(0, filesize) == "6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91"
}
```

### Sample 31: `8c6b26ab06165ec5`

| Field | Value |
|---|---|
| SHA-256 | `8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b` |
| Family label | `unknown` |
| File name | `8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b.bin` |
| File type | `exe` |
| First seen | `2026-09-09 01:53:46` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fb89d6f4b9d8664340bf6250e85d7a7` |
| SHA-1 | `41bc3c393e1a546bf51db11aa0f5e19577808fc1` |
| SHA-256 | `8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b` |
| SHA3-384 | `a243034d14cac0f8b40ab407d80407b155a5dff78770d673eb14412667a0fc522b9a852973cb6e630a71b9ff0c433ed3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1CE366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaW:uc3XND1aJrCOkW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_8c6b26ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b"
    family = "unknown"
    file_name = "8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b.bin"
    file_type = "exe"
    first_seen = "2026-09-09 01:53:46"
  condition:
    hash.sha256(0, filesize) == "8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b"
}
```

### Sample 32: `8e8321260017a015`

| Field | Value |
|---|---|
| SHA-256 | `8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8` |
| Family label | `unknown` |
| File name | `8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8.bin` |
| File type | `exe` |
| First seen | `2026-09-09 01:53:43` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25d51cffd2ef204a9e6564e5c62dcae3` |
| SHA-1 | `aa0799fda9a9e9853e4ec57fecc4ec5d3beec44c` |
| SHA-256 | `8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8` |
| SHA3-384 | `b562199099f4a65c59f85dcf7a74d6c9b3a2cf6fcac6b483e11f07ddfccd568929c837265e98bbd492be3c7db741af50` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T124366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaag:uc3XND1aJrCOkg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_8e832126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8"
    family = "unknown"
    file_name = "8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8.bin"
    file_type = "exe"
    first_seen = "2026-09-09 01:53:43"
  condition:
    hash.sha256(0, filesize) == "8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8"
}
```

### Sample 33: `e12dbf049019f00e`

| Field | Value |
|---|---|
| SHA-256 | `e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6` |
| Family label | `VShell` |
| File name | `e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6.exe` |
| File type | `exe` |
| First seen | `2026-09-09 01:08:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2a5db8ee303bb338f754a8e5875b560` |
| SHA-1 | `003282b13fec5446f26687a530a0afada47b8cac` |
| SHA-256 | `e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6` |
| SHA3-384 | `4299e6447a04b407357264abb2b708cb62b4c5ea2e27edc7d3bbc91787f898134de49f65558318f7f7ebcd3288b7bb2c` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E871B54160501AF2D94CE3BF8487B895FD4EB288A2C84B0B0798D81A2F7647BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6D78jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6D7G++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_033_e12dbf04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6"
    family = "VShell"
    file_name = "e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6.exe"
    file_type = "exe"
    first_seen = "2026-09-09 01:08:41"
  condition:
    hash.sha256(0, filesize) == "e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6"
}
```

### Sample 34: `e3e5faa2660cd86e`

| Field | Value |
|---|---|
| SHA-256 | `e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22` |
| Family label | `Mirai` |
| File name | `e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22.elf` |
| File type | `elf` |
| First seen | `2026-09-09 00:58:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8909d4ca3383f068bcb32bf35b40d2f` |
| SHA-1 | `3fcf95830809235e72c104882e9e882eecc9541a` |
| SHA-256 | `e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22` |
| SHA3-384 | `02934f1e4e8c78d5fc6a68a808631ced9ca2a31ee2398f2b8cace56332d6315a056bbdd158b2ef86b76f2eb23482865a` |
| TLSH | `T18C437C8AE993D1F1E69349710017DB9AAB38DE358004DE4AFB497932ECB17D3965B30C` |
| TELFHASH | `t1423107b57e7608fdf7c0a859cb0fa6838b26da770a10607e05f5294237f1e319531835` |
| SSDEEP | `1536:rQtfQ21I9pwHUqKJgsYUryt2W8aO2DZ8n9Jor:rQtfQ2ujwHU9JgsYLt2DaOc2A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_e3e5faa2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22"
    family = "Mirai"
    file_name = "e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22.elf"
    file_type = "elf"
    first_seen = "2026-09-09 00:58:42"
  condition:
    hash.sha256(0, filesize) == "e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22"
}
```

### Sample 35: `b9a8f948feb4057a`

| Field | Value |
|---|---|
| SHA-256 | `b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077` |
| Family label | `Mirai` |
| File name | `b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077.elf` |
| File type | `elf` |
| First seen | `2026-09-09 00:34:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `631b794dc371f47a561aed62d90201f8` |
| SHA-1 | `469cd0c2a923506a6c208251d6ef41a12ecfce38` |
| SHA-256 | `b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077` |
| SHA3-384 | `b13bfd781dc8f9f7812fcf07b74a76f5dc416d94128832fa0979294e48d298ca5da902ef7fef6dc8d791b007afbf3306` |
| TLSH | `T1DE436B8ADA93E1F1E69349710057DB8AAB78DE358008DE86FB097532ECF17D2565B30C` |
| TELFHASH | `t17a316bb47e6508ecf7d0f899c70f96938f6ac6730721657a01f1690137f2e619522835` |
| SSDEEP | `1536:f+1vlL0F/IWUqHm5mV4vIU9fhWSa5oIZGV9ior:f+1vlL0ZIWZHm0V4vIQfhha5FMj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_b9a8f948
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077"
    family = "Mirai"
    file_name = "b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077.elf"
    file_type = "elf"
    first_seen = "2026-09-09 00:34:16"
  condition:
    hash.sha256(0, filesize) == "b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077"
}
```

### Sample 36: `e7be5fda5fc08571`

| Field | Value |
|---|---|
| SHA-256 | `e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357` |
| Family label | `unknown` |
| File name | `e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357.bin` |
| File type | `exe` |
| First seen | `2026-09-09 00:28:56` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0925803a819f9eb4ddf4a821a99ec73b` |
| SHA-1 | `7e6c69e634ef3e77d3fa8c44d61db1a8a674902a` |
| SHA-256 | `e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357` |
| SHA3-384 | `6211c6828de488f4dc3acb5febf967820eede702e6b8b913b49d1cb91e7aa9dabbc120a97df2772707b719e949cdd6bb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11B567C437F8181A0C095EA3A84F642617B787C0D873433AB6EA5A9703F7A3D1B675F64` |
| SSDEEP | `49152:L5tX7HzAKsVqkTeqNjWIreE6tzcDiYi7vzPDd5OF5V7QVBtNffqVgGNGeflWszwn:L/naldreIOY47d6T7QVNf1GFN3s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_e7be5fda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357"
    family = "unknown"
    file_name = "e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357.bin"
    file_type = "exe"
    first_seen = "2026-09-09 00:28:56"
  condition:
    hash.sha256(0, filesize) == "e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357"
}
```

### Sample 37: `f341190f94840430`

| Field | Value |
|---|---|
| SHA-256 | `f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3` |
| Family label | `VShell` |
| File name | `f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3.exe` |
| File type | `exe` |
| First seen | `2026-09-09 00:08:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6ce703f83dc09e0f13f9d0ae60543da` |
| SHA-1 | `6662cab084ad1a0f2028dacb2170f95ff403beb2` |
| SHA-256 | `f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3` |
| SHA3-384 | `d65f7028ecc16167f225145e21da583275804cfcf50767524907851bdf6ce37b61bf13e865eba3587c06739e69bc3faf` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1A7716188F3176AF1E43C47F800D3A614C459ABB8C250BF4D5E60381D3C220BA255EF97` |
| SSDEEP | `48:6Icwm0It2WSJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jdtQSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_037_f341190f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3"
    family = "VShell"
    file_name = "f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3.exe"
    file_type = "exe"
    first_seen = "2026-09-09 00:08:51"
  condition:
    hash.sha256(0, filesize) == "f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3"
}
```

### Sample 38: `c3e430b1716764ca`

| Field | Value |
|---|---|
| SHA-256 | `c3e430b1716764ca82d8a25db5d19e2239018bf426e7c6d4b5e769ddce469ad9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-08 23:40:50` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a5b71df1b5fd762fdc5e54dcda9257a` |
| SHA-1 | `9cb16ea9b24605f185b679a19210ea838cb3bc9c` |
| SHA-256 | `c3e430b1716764ca82d8a25db5d19e2239018bf426e7c6d4b5e769ddce469ad9` |
| SHA3-384 | `0f8701537699caeca995bf38dc783dde774396353ce31e44f7ab70a6398a40117054049bdddb0c6e460c5360b1632594` |
| IMPHASH | `d840933770682f7204ccca58e56807be` |
| TLSH | `T181A68C43F26280F8C16AC075935A6233FA227C894B3479EB5BE44B253E65FD06B3DB54` |
| SSDEEP | `196608:S9jApIzhdUHXGVwVs5ZuHa7kWXe4+eNIrSV:SqpIh3vZ3FO4+eNIrS` |
| ICON-DHASH | `8051716971693296` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_c3e430b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3e430b1716764ca82d8a25db5d19e2239018bf426e7c6d4b5e769ddce469ad9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 23:40:50"
  condition:
    hash.sha256(0, filesize) == "c3e430b1716764ca82d8a25db5d19e2239018bf426e7c6d4b5e769ddce469ad9"
}
```

### Sample 39: `82a4e2fe38d95392`

| Field | Value |
|---|---|
| SHA-256 | `82a4e2fe38d95392e19f9b8618df2ce0811d40a1aabc3a226b4d4c69a0bd5e7c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-08 23:37:41` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65d98d37e51605121247c12c4ed8ada4` |
| SHA-1 | `4aa72f90da06e4b8be48de6d6b8a1fb81209c7ba` |
| SHA-256 | `82a4e2fe38d95392e19f9b8618df2ce0811d40a1aabc3a226b4d4c69a0bd5e7c` |
| SHA3-384 | `44c847fd7f24b89e1f76a8113598cc483165d0270676c3f2668f392949302489718ce5140f5affbdd12bfc123ab5aca1` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T169F6E0037B5450D5E565D935C93BA267E620BC4C9B3223D73E60B4312EFA3E068BAF19` |
| SSDEEP | `196608:0bkKueOj8m0EoJdGRFAPlzAj5Pt2goWgq2s6iGBduGKN372OwkroCR+uj9:0x7Oj30EoJdGPARghCqXGWGaqk+69` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_82a4e2fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a4e2fe38d95392e19f9b8618df2ce0811d40a1aabc3a226b4d4c69a0bd5e7c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 23:37:41"
  condition:
    hash.sha256(0, filesize) == "82a4e2fe38d95392e19f9b8618df2ce0811d40a1aabc3a226b4d4c69a0bd5e7c"
}
```

### Sample 40: `9dea0a840f4925b3`

| Field | Value |
|---|---|
| SHA-256 | `9dea0a840f4925b3a5d7b25d9c6281838ec3247b6938c3883d7f3b98545e71b1` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-09-08 23:13:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e393a3c9daec276e02d9e071ff204fd` |
| SHA-1 | `044550d34883c05943ab30e68c15ccf6a615f863` |
| SHA-256 | `9dea0a840f4925b3a5d7b25d9c6281838ec3247b6938c3883d7f3b98545e71b1` |
| SHA3-384 | `b21012fc843ff0ddf6bc8ba1311bde95c32f6964d62c14afaa6fa81a03d2e4929bd4ffe51f912b2483524d45ed47eac1` |
| TLSH | `T101E33B16FA808B53C0D61B76BA9B825533239B54E3E733069928BFB43F8375D4E27506` |
| TELFHASH | `t1be31cc36a7214622ab61cc6098e993a3022dc7165248fb73cf32c49c541a0eae637c5f` |
| SSDEEP | `3072:/sRsUR6aaibTkem39Lz44L1NXWSJPvM/9xz0R810:0Rb6aaibTkemtL9nmSJXM/9v10` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_9dea0a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dea0a840f4925b3a5d7b25d9c6281838ec3247b6938c3883d7f3b98545e71b1"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-09-08 23:13:34"
  condition:
    hash.sha256(0, filesize) == "9dea0a840f4925b3a5d7b25d9c6281838ec3247b6938c3883d7f3b98545e71b1"
}
```

### Sample 41: `c630cb386ed061f3`

| Field | Value |
|---|---|
| SHA-256 | `c630cb386ed061f395b2527513b40f45d5c857637856cdacef856a6b061ff277` |
| Family label | `Mirai` |
| File name | `boatnet.arc` |
| File type | `elf` |
| First seen | `2026-09-08 23:13:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f85fc8056e1313acce0322073538ea78` |
| SHA-1 | `d2e13e8caea45015169d3f34d609220dc8824129` |
| SHA-256 | `c630cb386ed061f395b2527513b40f45d5c857637856cdacef856a6b061ff277` |
| SHA3-384 | `48e22b07839fb4ef1188024426eb544fdb11078d4872bfc0ddcbc43b1c847c6eeaa1cb1b19cce6df1f6244e508fd03bf` |
| TLSH | `T112B39CDBF24701A0C8624AF007CB4BED3E2723815F27C5E72C6A657968791CF8906F96` |
| SSDEEP | `1536:Fu27gBY9FSSpj3z5Qxw6YaWWgg1x/LWy:c9sSyzz36YaWWgg1xq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_c630cb38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c630cb386ed061f395b2527513b40f45d5c857637856cdacef856a6b061ff277"
    family = "Mirai"
    file_name = "boatnet.arc"
    file_type = "elf"
    first_seen = "2026-09-08 23:13:32"
  condition:
    hash.sha256(0, filesize) == "c630cb386ed061f395b2527513b40f45d5c857637856cdacef856a6b061ff277"
}
```

### Sample 42: `67c4c5ac61391f6f`

| Field | Value |
|---|---|
| SHA-256 | `67c4c5ac61391f6faa60aa021e66b7fed80aab9f9d3f2cae1f6b008b42b126cf` |
| Family label | `unknown` |
| File name | `trouserstreak.net__trouser-streak-1.6.1-1.21.4.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:01:24` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3438b3f2931dacc62d3cdc47b1ba05ba` |
| SHA-1 | `30aaca096b582c3f4a7e50f2c7a7a1450779cff1` |
| SHA-256 | `67c4c5ac61391f6faa60aa021e66b7fed80aab9f9d3f2cae1f6b008b42b126cf` |
| SHA3-384 | `1f147ea86bacfdc3ad35ef0e8a0469c6994570b10730fa213bdcfdd3b44427342947d8ab86987a583aad1ac8161ce33e` |
| TLSH | `T1C2051216662B162FD216F239B4578DE1BEF94AE4710D64EA02FCC185C0439FF1BA16BC` |
| SSDEEP | `24576:YufI6NiPsvImGbKKzIEi+2m2WhA4QFtd1OKIIXfn0y+tPjx:EMzKKKzIEi+2xCwFTKys` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_67c4c5ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67c4c5ac61391f6faa60aa021e66b7fed80aab9f9d3f2cae1f6b008b42b126cf"
    family = "unknown"
    file_name = "trouserstreak.net__trouser-streak-1.6.1-1.21.4.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:24"
  condition:
    hash.sha256(0, filesize) == "67c4c5ac61391f6faa60aa021e66b7fed80aab9f9d3f2cae1f6b008b42b126cf"
}
```

### Sample 43: `9053f8d71dcc6327`

| Field | Value |
|---|---|
| SHA-256 | `9053f8d71dcc63275a24bbaa1be86d963ce3165e58343f0b29649855b7162f8c` |
| Family label | `unknown` |
| File name | `trouserstreak.net__trouser-streak-1.6.1-1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:01:17` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18d98f41268178c0bd7703a908ed94a3` |
| SHA-1 | `309375056352847b5d0eccac56baf0e2890cf683` |
| SHA-256 | `9053f8d71dcc63275a24bbaa1be86d963ce3165e58343f0b29649855b7162f8c` |
| SHA3-384 | `f759ff9f5b844b2d1a01df0bc24cddccc4f078e99e823f388d3c73b163d350d75d43aec6b00e8a07ea82912fd9066ca4` |
| TLSH | `T141151211B277422BD61BE138B85B8CD1BDFC59E8764CA59A02FCC0C0E5425BF1B61ABD` |
| SSDEEP | `24576:ukYZiPhK4sIWzjXwpz5c1yMl4RO1Ers6WPOO:E5zjgpz5cIq492` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_9053f8d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9053f8d71dcc63275a24bbaa1be86d963ce3165e58343f0b29649855b7162f8c"
    family = "unknown"
    file_name = "trouserstreak.net__trouser-streak-1.6.1-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:17"
  condition:
    hash.sha256(0, filesize) == "9053f8d71dcc63275a24bbaa1be86d963ce3165e58343f0b29649855b7162f8c"
}
```

### Sample 44: `f72cecb79c59fc50`

| Field | Value |
|---|---|
| SHA-256 | `f72cecb79c59fc50cde41400d9ca422d303cd444769e7ec9423889136a7a93aa` |
| Family label | `unknown` |
| File name | `meteorrejects.net__meteor-rejects-addon-1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:01:11` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c038d81cf591ebd5ca834c670c8fce83` |
| SHA-1 | `0b26498a4c669a1ee22d65d3a4a5b170ce3b9719` |
| SHA-256 | `f72cecb79c59fc50cde41400d9ca422d303cd444769e7ec9423889136a7a93aa` |
| SHA3-384 | `4e5d314cdcde3a0511ef958d8fdffe80311c2978130be4d9247ab82d4ae595a82053d9987d3e7d1c4edb83d05f2c5b20` |
| TLSH | `T1F3E51227E9D8C07FD867B33291025AA1B94D0AF3D00560FF16FC0ABAC9859DB27617D6` |
| SSDEEP | `49152:aWCBm2R3UT4+7hCLYILY757B2S6zJjnB/p2HR3MSMCbT1tZv9BV+5JS:fXVYsAFlbBUx3MJWjBse` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_f72cecb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f72cecb79c59fc50cde41400d9ca422d303cd444769e7ec9423889136a7a93aa"
    family = "unknown"
    file_name = "meteorrejects.net__meteor-rejects-addon-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:11"
  condition:
    hash.sha256(0, filesize) == "f72cecb79c59fc50cde41400d9ca422d303cd444769e7ec9423889136a7a93aa"
}
```

### Sample 45: `35222d50b11bc02b`

| Field | Value |
|---|---|
| SHA-256 | `35222d50b11bc02bfb6bcb3127b5a55179bbd1112042466d26799e7c08d86287` |
| Family label | `unknown` |
| File name | `novowareclient.com__inline-payload.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:01:03` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f10daf9d18f4a2f210b2e9d83c892313` |
| SHA-1 | `d404583ffb6f888ccfcd8b5dd5d18a1c6cae2651` |
| SHA-256 | `35222d50b11bc02bfb6bcb3127b5a55179bbd1112042466d26799e7c08d86287` |
| SHA3-384 | `58a482ff5eacd3d11a196355b64eefad31f54d3b2f7645a9dbf96c7b7e6e8cc5df682d06dc74f6e1db5856af4b6972c2` |
| TLSH | `T1B0C40166D84CCC3DE54B327510AF2F63901992B598C6A92B0670F78BC152ECA5F3E61F` |
| SSDEEP | `12288:eZy4bnePWquIofzcb6tNYluUkx5JfJarWFYIc16NgU:l4iHKwmo87ao6SgU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_35222d50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35222d50b11bc02bfb6bcb3127b5a55179bbd1112042466d26799e7c08d86287"
    family = "unknown"
    file_name = "novowareclient.com__inline-payload.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:03"
  condition:
    hash.sha256(0, filesize) == "35222d50b11bc02bfb6bcb3127b5a55179bbd1112042466d26799e7c08d86287"
}
```

### Sample 46: `81626e1e1cd90448`

| Field | Value |
|---|---|
| SHA-256 | `81626e1e1cd90448bd07f46ae54efa2e3a0682986a28a11a77d8b436db880d92` |
| Family label | `unknown` |
| File name | `meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc26_1_2.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:00:54` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eee849d6486e40e41423d96c8703089f` |
| SHA-1 | `cbc8090ccffcc6ddeb378343cd45a00d21a68640` |
| SHA-256 | `81626e1e1cd90448bd07f46ae54efa2e3a0682986a28a11a77d8b436db880d92` |
| SHA3-384 | `ce2511a0afc75d52c724bfafcae96eaea4723c0a9786c15aeb5441c780ce9ff04ae6230c6897d76583bb6481fb3a0760` |
| TLSH | `T11A94F0E7671ADEA7E53F467C81A31F82F91A329ED80770631D14B20B853BDCD613099A` |
| SSDEEP | `12288:Ycliv2YB+N4OaKxXWKxNFkSHIF1mwspYR1DcwoPdt:Yuiv2A+N4OanKxYSHq1mRpYRxoPdt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_81626e1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81626e1e1cd90448bd07f46ae54efa2e3a0682986a28a11a77d8b436db880d92"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc26_1_2.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:54"
  condition:
    hash.sha256(0, filesize) == "81626e1e1cd90448bd07f46ae54efa2e3a0682986a28a11a77d8b436db880d92"
}
```

### Sample 47: `29ad567237511d62`

| Field | Value |
|---|---|
| SHA-256 | `29ad567237511d625f13a68132875460399aac101ec9ae6a3d43e3bfbb6a4aa0` |
| Family label | `unknown` |
| File name | `meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_11.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:00:48` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3a253443985bea72d660fc38207989d` |
| SHA-1 | `0321f39ceff287f50498fc867c11706f48745662` |
| SHA-256 | `29ad567237511d625f13a68132875460399aac101ec9ae6a3d43e3bfbb6a4aa0` |
| SHA3-384 | `4c6a65e11cbc055e1bd66d7dea93d74c01db3214914b7321f92fa146b57cc9a3e39b561a270d3d1273983cde5be0a44c` |
| TLSH | `T16B94E0EB5A09DEABD13B567C85631FD1B5143381E806706F0E64E24B813BA9F2334E5E` |
| SSDEEP | `12288:xCgJFlQmwspYR1Dc0k+ar2/dN2khzF5O52C:IgJAmRpYRzk+M2lgsF5Oh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_29ad5672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ad567237511d625f13a68132875460399aac101ec9ae6a3d43e3bfbb6a4aa0"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_11.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:48"
  condition:
    hash.sha256(0, filesize) == "29ad567237511d625f13a68132875460399aac101ec9ae6a3d43e3bfbb6a4aa0"
}
```

### Sample 48: `3dcc6c98de31c510`

| Field | Value |
|---|---|
| SHA-256 | `3dcc6c98de31c5100a71f6ccc21597ca80ec40ddb11a21f3b924cde42816c622` |
| Family label | `unknown` |
| File name | `meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_10.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:00:42` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `411b2c1202f7b1e51089b9fc186e6e22` |
| SHA-1 | `149da2f2d7b801380e6ab1f7c4d4df5478392688` |
| SHA-256 | `3dcc6c98de31c5100a71f6ccc21597ca80ec40ddb11a21f3b924cde42816c622` |
| SHA3-384 | `03798786d8da734b88d1e61b5094ef2abf4f895cbbe995a5cea2f423ca42475f97ff96551ccb2dcac36682e6a4e61be4` |
| TLSH | `T11BA4E0E79A4AEE9BD03F167945630FC1B5143381E806706F0E64E24B847B98F2735E9E` |
| SSDEEP | `12288:117nvGBmwspYR1Dcfk+aN/dt2khzFNtFHSY:r7neBmRpYRMk+alAsFNn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_3dcc6c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dcc6c98de31c5100a71f6ccc21597ca80ec40ddb11a21f3b924cde42816c622"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_10.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:42"
  condition:
    hash.sha256(0, filesize) == "3dcc6c98de31c5100a71f6ccc21597ca80ec40ddb11a21f3b924cde42816c622"
}
```

### Sample 49: `5d5c3836211ea4d7`

| Field | Value |
|---|---|
| SHA-256 | `5d5c3836211ea4d757334687b12105d4e9f842ad9f6ee7ef655185e98c02e12a` |
| Family label | `unknown` |
| File name | `meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_4.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:00:35` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7f14e87142705312a5fdbe4390b4e95` |
| SHA-1 | `a55537af0badd2a23de6749da1c776724379c4a5` |
| SHA-256 | `5d5c3836211ea4d757334687b12105d4e9f842ad9f6ee7ef655185e98c02e12a` |
| SHA3-384 | `98ac2b35f011850e03343de034147b4e854741bd04ece9dcb3ae2b26df51db10435c2b8ebe9ae52ac0c18272e4494773` |
| TLSH | `T1FAA4E0DB9B4ADEAAD12F467C44531FC1B6083391E806706F0E64F24B847B98F2735A5E` |
| SSDEEP | `12288:DQk97mwspYR1DcjkyzZQh/z+hzFGMlOpfaOvM:kkNmRpYRgkyuL6FMpCOvM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_5d5c3836
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5c3836211ea4d757334687b12105d4e9f842ad9f6ee7ef655185e98c02e12a"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_4.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:35"
  condition:
    hash.sha256(0, filesize) == "5d5c3836211ea4d757334687b12105d4e9f842ad9f6ee7ef655185e98c02e12a"
}
```

### Sample 50: `a0d5fc7c7125ea1b`

| Field | Value |
|---|---|
| SHA-256 | `a0d5fc7c7125ea1b4803a4059db8a3b88282e0fb13df14c02d334a368dbe2cc8` |
| Family label | `unknown` |
| File name | `meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_1.jar` |
| File type | `jar` |
| First seen | `2026-09-08 23:00:29` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a473e8b985ff965ee8c46a69a55ee874` |
| SHA-1 | `ac862e405f1c5cd8a6d28971fe8126962e19eebc` |
| SHA-256 | `a0d5fc7c7125ea1b4803a4059db8a3b88282e0fb13df14c02d334a368dbe2cc8` |
| SHA3-384 | `06cbc7dbc00b09fe0b6cf11d38fd83f93df6d865110214273d78c083ad3124248ac39b26c6635f9f989d2f7e6065d611` |
| TLSH | `T1A7A4E0DB974ADEAAD13F577804531FC1BA083385E806706F0E64F24B943B98F2735A5A` |
| SSDEEP | `12288:jI03xmwspYR1DcAd2kyzZQh/U+hzFGMlOpfaOc:jLmRpYRFd2kyu86FMpCOc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_a0d5fc7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0d5fc7c7125ea1b4803a4059db8a3b88282e0fb13df14c02d334a368dbe2cc8"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_1.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:29"
  condition:
    hash.sha256(0, filesize) == "a0d5fc7c7125ea1b4803a4059db8a3b88282e0fb13df14c02d334a368dbe2cc8"
}
```

### Sample 51: `62c07b174de63a50`

| Field | Value |
|---|---|
| SHA-256 | `62c07b174de63a5035ce50fb11a9c1636e26fde96a0f368df1e71e7789f73230` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-08 22:50:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b909051ab654021745cd505216f4605c` |
| SHA-1 | `cfd738aff1b3f9eee031b1442c49b7ae3dacf62f` |
| SHA-256 | `62c07b174de63a5035ce50fb11a9c1636e26fde96a0f368df1e71e7789f73230` |
| SHA3-384 | `8b52b586654e4741e450289af28a3f6bc9259cd5abdf7ab8ed078b7e706d899ec000057638fb33786675bada7841db50` |
| TLSH | `T19DC28D966E867C44BEC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:O8vCB+25j6es8R29FYpMSUpi+20qUpi+20YQX:O8l25Jgd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_62c07b17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c07b174de63a5035ce50fb11a9c1636e26fde96a0f368df1e71e7789f73230"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-08 22:50:32"
  condition:
    hash.sha256(0, filesize) == "62c07b174de63a5035ce50fb11a9c1636e26fde96a0f368df1e71e7789f73230"
}
```

### Sample 52: `c19d15ff0145110b`

| Field | Value |
|---|---|
| SHA-256 | `c19d15ff0145110b8f9357c14ae5c61f92fc7eb20e5b2a1953c70a6673ac7530` |
| Family label | `Mirai` |
| File name | `titan.mipsel` |
| File type | `elf` |
| First seen | `2026-09-08 22:48:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78aa4549d9ad093a8f5e40d00f83983e` |
| SHA-1 | `3819c5b599276ace85635b52c9d8ef409bbd254b` |
| SHA-256 | `c19d15ff0145110b8f9357c14ae5c61f92fc7eb20e5b2a1953c70a6673ac7530` |
| SHA3-384 | `4dacab107f603433055f3417757dfb7a5147aee9b274477039734c5b1f6e0e5a96d4692bd20468f18ea662ab0efb8ee9` |
| TLSH | `T118744B07FE408AEBF81BCDB0C9BEC3923DF561D756F96539617889AC3E6B10A0493494` |
| SSDEEP | `6144:gtSWfLgETBKs/b9vvTw4hBRecObPNP52y83kyhTQOmoOq:gtSWE+vtTRjQld83kyhTQO/O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_c19d15ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c19d15ff0145110b8f9357c14ae5c61f92fc7eb20e5b2a1953c70a6673ac7530"
    family = "Mirai"
    file_name = "titan.mipsel"
    file_type = "elf"
    first_seen = "2026-09-08 22:48:56"
  condition:
    hash.sha256(0, filesize) == "c19d15ff0145110b8f9357c14ae5c61f92fc7eb20e5b2a1953c70a6673ac7530"
}
```

### Sample 53: `86953022ccd295b0`

| Field | Value |
|---|---|
| SHA-256 | `86953022ccd295b02be2202be2e2d9d8d87ef719d1aa368ca16c30a33fcdbd63` |
| Family label | `unknown` |
| File name | `KiddonsModMenu.exe` |
| File type | `exe` |
| First seen | `2026-09-08 22:39:47` |
| Reporter | `burger403` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f190d6ebbcc3810333712c48c12ffb2b` |
| SHA-1 | `d6744769778a4760b289303075eadc594a288e98` |
| SHA-256 | `86953022ccd295b02be2202be2e2d9d8d87ef719d1aa368ca16c30a33fcdbd63` |
| SHA3-384 | `b02f24fad349db15aad159421f61ea8d163f396b312acaecb4b5d86f53b28c1d4d17660cd95441134255a3b50c51a435` |
| IMPHASH | `fac9b28d69ff8f4084e9d07b45254cfc` |
| TLSH | `T1A8C623EA5AD853B0D4525540A58B43EA30C1BA0E85FD4D1A39DB2E426B18CBF214FFF7` |
| SSDEEP | `196608:bMk9ms2JtuyCy1FJqI4eb4lK3FA4XygWwW5OiB2RgvtgL60NiMsy3Dp7Sxzz:bMsuJ1HqI4ebnGgoFBKctw3F7SxP` |
| ICON-DHASH | `421cf8c0c0e060e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_86953022
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86953022ccd295b02be2202be2e2d9d8d87ef719d1aa368ca16c30a33fcdbd63"
    family = "unknown"
    file_name = "KiddonsModMenu.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:39:47"
  condition:
    hash.sha256(0, filesize) == "86953022ccd295b02be2202be2e2d9d8d87ef719d1aa368ca16c30a33fcdbd63"
}
```

### Sample 54: `71866496dfb4b741`

| Field | Value |
|---|---|
| SHA-256 | `71866496dfb4b741274cdba933e8f9fe0209542e5198d8e9b240d967070bc1c4` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-08 22:38:34` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9bd9d0d1e61a8393c060d9825ba6dc6` |
| SHA-256 | `71866496dfb4b741274cdba933e8f9fe0209542e5198d8e9b240d967070bc1c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_71866496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71866496dfb4b741274cdba933e8f9fe0209542e5198d8e9b240d967070bc1c4"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-08 22:38:34"
  condition:
    hash.sha256(0, filesize) == "71866496dfb4b741274cdba933e8f9fe0209542e5198d8e9b240d967070bc1c4"
}
```

### Sample 55: `007e5fba613f08c7`

| Field | Value |
|---|---|
| SHA-256 | `007e5fba613f08c75b4073409e63b03622623a4d12b25ab8bca74bb68db77f5b` |
| Family label | `unknown` |
| File name | `executorfree.exe` |
| File type | `exe` |
| First seen | `2026-09-08 22:37:45` |
| Reporter | `burger403` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1697192d8b707f96dc3ee1c409771b61` |
| SHA-1 | `8dfcde94065c4858328741d9886e74fcb97143f0` |
| SHA-256 | `007e5fba613f08c75b4073409e63b03622623a4d12b25ab8bca74bb68db77f5b` |
| SHA3-384 | `07ea2424e240183cbf7c66c073b5f70a1292676cd95f8d7f4cc7d386484b2813ef338bff35cae9e3032f55f404347a9b` |
| IMPHASH | `e715424ebef62edcf8229c713419932e` |
| TLSH | `T115162319DBF569B8F0B3A5329E624826EBB37C094B305A9F139949975F33AC04D39313` |
| SSDEEP | `98304:MCf9xH6tE/9WFJgJEE/ZMuMg/5FePiSSS/VQBmFxcSVUT8GEXqqn:BFxHiE2aVDbrkISd/FxhVUUH` |
| ICON-DHASH | `00b28e8e86868600` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_007e5fba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "007e5fba613f08c75b4073409e63b03622623a4d12b25ab8bca74bb68db77f5b"
    family = "unknown"
    file_name = "executorfree.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:37:45"
  condition:
    hash.sha256(0, filesize) == "007e5fba613f08c75b4073409e63b03622623a4d12b25ab8bca74bb68db77f5b"
}
```

### Sample 56: `b350924ace363c1d`

| Field | Value |
|---|---|
| SHA-256 | `b350924ace363c1d4980aa1d5022d48f4591df1c701d32c5147428273dfa56a8` |
| Family label | `unknown` |
| File name | `larpexodus.exe` |
| File type | `exe` |
| First seen | `2026-09-08 22:36:29` |
| Reporter | `burger403` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d505883d927ca1e4a211c3bae9cd963f` |
| SHA-1 | `b42628b8deb1168c48693dbabf1d6fa04aa9df2c` |
| SHA-256 | `b350924ace363c1d4980aa1d5022d48f4591df1c701d32c5147428273dfa56a8` |
| SHA3-384 | `342a6604ba08bf96adc7a75e2ae7310a3fe1c29be674940ff3f431818c2e16ae5c461f8153b23b5a1ea2be6765528169` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1CC283391A6AC5014ED7DFC76F36CF36F212D8E0E4C0085AB05F61134BBA06B2B65EB56` |
| SSDEEP | `1572864:NuyFfaRGpG48TwYqtSqF+1GohGuESDQ+c/dUxIlX+jHj00EKV0X7NzvLWCnbo97:NuyZa04wYoFvuE4Nq6IlX+jHj09oCns7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_b350924a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b350924ace363c1d4980aa1d5022d48f4591df1c701d32c5147428273dfa56a8"
    family = "unknown"
    file_name = "larpexodus.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:36:29"
  condition:
    hash.sha256(0, filesize) == "b350924ace363c1d4980aa1d5022d48f4591df1c701d32c5147428273dfa56a8"
}
```

### Sample 57: `97921a2cfacb0b73`

| Field | Value |
|---|---|
| SHA-256 | `97921a2cfacb0b73fc7d14e29b751862b4bd0f02972d2af64cfdf8e0e802ab6f` |
| Family label | `Mirai` |
| File name | `titan.x64-test` |
| File type | `elf` |
| First seen | `2026-09-08 22:30:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd89e49453c4c024366acffb8937ad54` |
| SHA-1 | `aa358203fee62684ccd938c682e935c99b3f093a` |
| SHA-256 | `97921a2cfacb0b73fc7d14e29b751862b4bd0f02972d2af64cfdf8e0e802ab6f` |
| SHA3-384 | `65c756eaa5223796578739418fc2cc5189bcdf2e8dbc0cfdbeebb9370df6d5180c562f534616bef509bca23bea37db47` |
| TLSH | `T186456C5AF2F370FCC467C030835BDB62B835B46512226E7B65C49A352D62EB01B1AF67` |
| TELFHASH | `t101d191b08af974b0a6dbca15b322f0759e75193522ed36f41a35adc8ed00f801c6683b` |
| SSDEEP | `24576:4BjpPxIgdtwrgaIHjlvdkiwzqcQVRI8srFu:i/NGrgaIDlFkiwzqcQf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_97921a2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97921a2cfacb0b73fc7d14e29b751862b4bd0f02972d2af64cfdf8e0e802ab6f"
    family = "Mirai"
    file_name = "titan.x64-test"
    file_type = "elf"
    first_seen = "2026-09-08 22:30:35"
  condition:
    hash.sha256(0, filesize) == "97921a2cfacb0b73fc7d14e29b751862b4bd0f02972d2af64cfdf8e0e802ab6f"
}
```

### Sample 58: `96d443a8f6fbb22e`

| Field | Value |
|---|---|
| SHA-256 | `96d443a8f6fbb22ef7a1462d57b39591cbd465ba391a8c6e2c41fa3df7f92f0c` |
| Family label | `SilentNet` |
| File name | `fortnite loader.exe` |
| File type | `exe` |
| First seen | `2026-09-08 22:30:28` |
| Reporter | `burger403` |
| Tags | `exe, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b286238af9ae518c361a8106889c7d64` |
| SHA-1 | `8d94e524a7458a464c9395e2a2c71318f75111e7` |
| SHA-256 | `96d443a8f6fbb22ef7a1462d57b39591cbd465ba391a8c6e2c41fa3df7f92f0c` |
| SHA3-384 | `c5f4d8aa3c3572d4bb3e8714fa279400247647323bd2d45b62837c70d25eea0daf034239068b66f84e9c867113d2599f` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T191357C83E7A385D8C116C9B5534BF137F9627C8E4B157197ABC41E633A67BA4E22CB00` |
| SSDEEP | `12288:Xbs/m0E54jwaFXGc8lEBBBHGBKq2IZwDavfqItNqdg:XbOVE5ifGPRZwGvf3fd` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_058_96d443a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96d443a8f6fbb22ef7a1462d57b39591cbd465ba391a8c6e2c41fa3df7f92f0c"
    family = "SilentNet"
    file_name = "fortnite loader.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:30:28"
  condition:
    hash.sha256(0, filesize) == "96d443a8f6fbb22ef7a1462d57b39591cbd465ba391a8c6e2c41fa3df7f92f0c"
}
```

### Sample 59: `1a15976ce2e12f81`

| Field | Value |
|---|---|
| SHA-256 | `1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419` |
| Family label | `unknown` |
| File name | `1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419` |
| File type | `unknown` |
| First seen | `2026-09-08 22:30:24` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1be4a5342c3b345b55c7a784d29c549a` |
| SHA-256 | `1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_1a15976c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419"
    family = "unknown"
    file_name = "1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419"
    file_type = "unknown"
    first_seen = "2026-09-08 22:30:24"
  condition:
    hash.sha256(0, filesize) == "1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419"
}
```

### Sample 60: `2a64b441a105af29`

| Field | Value |
|---|---|
| SHA-256 | `2a64b441a105af29fd5fcd48bd7215f1044b045f85ba47d5b58cb888e1b20b74` |
| Family label | `Mirai` |
| File name | `titan.arm6` |
| File type | `elf` |
| First seen | `2026-09-08 22:24:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdb2216e3a1fc323cfff3cb15f2b5c00` |
| SHA-1 | `dabff7dec1beaee6f2768918c3187a782a1ae8f0` |
| SHA-256 | `2a64b441a105af29fd5fcd48bd7215f1044b045f85ba47d5b58cb888e1b20b74` |
| SHA3-384 | `80b24bf666c973dc82c11678c347a566e0a85118c9f04585dcbac7f9a364b38edf59bbc4a3199ebdf4d661a566f9df68` |
| TLSH | `T14B44184AFC41CE60F98106B6FA5E42D83B2303FBD7FE75019D150B742BA746A4E2B952` |
| TELFHASH | `t10ae0c2243ea4b3ae92a907c503fd9113ce06325e1b901aa2c94c2717a952fc2b02a533` |
| SSDEEP | `6144:QnYwoLAWnK8zbhPE+neubSSrWzZxEJA8BRD/8bkyhTQOmw/UqE:YYwAhhXneubqzZGA8v8bkyhTQOF/U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_2a64b441
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a64b441a105af29fd5fcd48bd7215f1044b045f85ba47d5b58cb888e1b20b74"
    family = "Mirai"
    file_name = "titan.arm6"
    file_type = "elf"
    first_seen = "2026-09-08 22:24:35"
  condition:
    hash.sha256(0, filesize) == "2a64b441a105af29fd5fcd48bd7215f1044b045f85ba47d5b58cb888e1b20b74"
}
```

### Sample 61: `3e7834229ec2359b`

| Field | Value |
|---|---|
| SHA-256 | `3e7834229ec2359bd079dc08736aefe31c67a9a2a15e90016e371e1416c39d19` |
| Family label | `unknown` |
| File name | `Simple Cheats Client.zip` |
| File type | `zip` |
| First seen | `2026-09-08 22:22:43` |
| Reporter | `burger403` |
| Tags | `pw-1337, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7373db6a7862a132cd6775578dc13f4` |
| SHA-1 | `6cf93d6d90fee5df0cf1982a675f902444156c55` |
| SHA-256 | `3e7834229ec2359bd079dc08736aefe31c67a9a2a15e90016e371e1416c39d19` |
| SHA3-384 | `d83ffd38969f28b7c41a2deae574345753d6683e136dbf013659579294b3864be9f75bfcc103ebc59da30711623b59cd` |
| TLSH | `T11718334B1433F88A1437A37CCC65FDB9A2595952978ABCC93B503C201669D32B7C68BF` |
| SSDEEP | `1572864:phIGkHiwiexFQYNbqUNKveU3j2lmXZuKQDWcMt3JHOhNRHgz:rIPCiQY1xFl4DcM1JHkdgz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_3e783422
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e7834229ec2359bd079dc08736aefe31c67a9a2a15e90016e371e1416c39d19"
    family = "unknown"
    file_name = "Simple Cheats Client.zip"
    file_type = "zip"
    first_seen = "2026-09-08 22:22:43"
  condition:
    hash.sha256(0, filesize) == "3e7834229ec2359bd079dc08736aefe31c67a9a2a15e90016e371e1416c39d19"
}
```

### Sample 62: `a19fce7dfd85822b`

| Field | Value |
|---|---|
| SHA-256 | `a19fce7dfd85822b3dcc3fad77b0d91ac2740fc5a739f5741a1d3294ca2135bb` |
| Family label | `unknown` |
| File name | `Loader.exe` |
| File type | `exe` |
| First seen | `2026-09-08 22:20:22` |
| Reporter | `burger403` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b2fbfab939314234562e355acf91af3` |
| SHA-1 | `a93c087ff20cfbb42937c7e8c102d562c215a6ae` |
| SHA-256 | `a19fce7dfd85822b3dcc3fad77b0d91ac2740fc5a739f5741a1d3294ca2135bb` |
| SHA3-384 | `50a11feb81db68b4cc87cb13e1624c9b30d4a2c7514cf16eef1e168f50e68cfe8798205d5582f15efd629da1bc0576eb` |
| IMPHASH | `fd6f6d07cc33ee9a2b65bda58a07bb94` |
| TLSH | `T146286C43A2E751D8F0BBD17496E65323E933BC490B3469EF12944B312F72AE0A779B11` |
| SSDEEP | `1572864:GZa7hmguP2nG0/Vyv7UhgxIabc/97Awb0:GZa7hmguP2nUOTAwb0` |
| ICON-DHASH | `9170cc9296cc7001` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_a19fce7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a19fce7dfd85822b3dcc3fad77b0d91ac2740fc5a739f5741a1d3294ca2135bb"
    family = "unknown"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:20:22"
  condition:
    hash.sha256(0, filesize) == "a19fce7dfd85822b3dcc3fad77b0d91ac2740fc5a739f5741a1d3294ca2135bb"
}
```

### Sample 63: `b20b400002fd59a8`

| Field | Value |
|---|---|
| SHA-256 | `b20b400002fd59a805b29118861b48480a0eb20001fc23561df311a93cef57f2` |
| Family label | `unknown` |
| File name | `decrypted_payload.exe` |
| File type | `exe` |
| First seen | `2026-09-08 22:16:54` |
| Reporter | `anonymous` |
| Tags | `exe, loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec85a96fa7b2da573c409ff298861eb3` |
| SHA-1 | `80f6cd7cf218938eac63e78205f302088023eaa1` |
| SHA-256 | `b20b400002fd59a805b29118861b48480a0eb20001fc23561df311a93cef57f2` |
| SHA3-384 | `6ce6ff7d12ea0bb55b8184adb47614979f080a74030c4f48566a6089c71177f2e5ef762f360dd9895c6d2f2337c431cf` |
| IMPHASH | `d62a3d2a3aa130db8fb7a7c4f51346ab` |
| TLSH | `T17DD47D21EAA811BDD0B7C1FDC9934C43E372B80B43355AEB07905AB61F169F95A3EB11` |
| SSDEEP | `12288:egYlfb80ZGZZ4CsGVC79QBNCRKj/vjyVo0dP1:e7TYZ1sso9RKfKt1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_b20b4000
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20b400002fd59a805b29118861b48480a0eb20001fc23561df311a93cef57f2"
    family = "unknown"
    file_name = "decrypted_payload.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:16:54"
  condition:
    hash.sha256(0, filesize) == "b20b400002fd59a805b29118861b48480a0eb20001fc23561df311a93cef57f2"
}
```

### Sample 64: `e2505b685cc4ab14`

| Field | Value |
|---|---|
| SHA-256 | `e2505b685cc4ab141172a1d2d70beb2e2683e4c96fb3f29e9a9c7476a0a1360d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-08 22:14:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58bd6346c89a7466fbf288e45c163d6e` |
| SHA-1 | `4a19c446e5e65d613e3a7933be423f213214a3a6` |
| SHA-256 | `e2505b685cc4ab141172a1d2d70beb2e2683e4c96fb3f29e9a9c7476a0a1360d` |
| SHA3-384 | `f084f23bd6567b8acd38cc900e480caf319398da1c7776b6236ccf6120e57192c89304f06067a4c59f7a687dde274a84` |
| TLSH | `T15AC27C966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:38vCB+25j6es8Re9FYpMSUpi+20qUpi+20YQX:38l25J4d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_e2505b68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2505b685cc4ab141172a1d2d70beb2e2683e4c96fb3f29e9a9c7476a0a1360d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-08 22:14:33"
  condition:
    hash.sha256(0, filesize) == "e2505b685cc4ab141172a1d2d70beb2e2683e4c96fb3f29e9a9c7476a0a1360d"
}
```

### Sample 65: `e3da33cd23e733ec`

| Field | Value |
|---|---|
| SHA-256 | `e3da33cd23e733ec215120582627110a37c6b97bfdefd36534240fd29b807016` |
| Family label | `unknown` |
| File name | `Taiwanske.vbs` |
| File type | `vbs` |
| First seen | `2026-09-08 22:12:28` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfb19edda3d4df6d44cbf0d1f047c17f` |
| SHA-1 | `9bf1136a9f76e8ccdd8426f7ea626369cbabbe74` |
| SHA-256 | `e3da33cd23e733ec215120582627110a37c6b97bfdefd36534240fd29b807016` |
| SHA3-384 | `37ca0c508833b9d465871169ab5c2631ba6a35b4ee832174a1b8e076e0200ccb63b60613e07dc8855ea86d2f37112712` |
| TLSH | `T182C25BA0AE2622E74A5F36F7CC998D70C9A40052012744B0BDFCB359695834CB7EE77B` |
| SSDEEP | `768:GpSmJqpwDZzeWmqAzUHAuu0JcLSS6DMkD+hLw6qj2yFTe:Nmoapmqd1oUzD+Kj2me` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_e3da33cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3da33cd23e733ec215120582627110a37c6b97bfdefd36534240fd29b807016"
    family = "unknown"
    file_name = "Taiwanske.vbs"
    file_type = "vbs"
    first_seen = "2026-09-08 22:12:28"
  condition:
    hash.sha256(0, filesize) == "e3da33cd23e733ec215120582627110a37c6b97bfdefd36534240fd29b807016"
}
```

### Sample 66: `f3194a746e0b91fa`

| Field | Value |
|---|---|
| SHA-256 | `f3194a746e0b91fa649eed5ccb0d43e1eb4cb87d41249fb5f38bd2740b9bbca0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-08 22:04:47` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17940eb2131c50138239c1d754d74003` |
| SHA-1 | `1e4c76664b5a2338fe384b2a2b213da4e3d6bd12` |
| SHA-256 | `f3194a746e0b91fa649eed5ccb0d43e1eb4cb87d41249fb5f38bd2740b9bbca0` |
| SHA3-384 | `245cfd7121de5b7ec7e8cfd7fed12bea314bd98b9274d2fbb39b309f67904e23eb178fb1a43fca940dd7e6f8c590411f` |
| IMPHASH | `300304ba47eeb447001eb41156f8b49c` |
| TLSH | `T1612633A7917B883BD4165839B5CA0EA1EC309329C1EEABB07E871C01D5F6B34D54B778` |
| SSDEEP | `98304:xXajIKvT+f6mZZJ2dq7v9HlwwoKu6LHPnZAUvWOf4uX:xbKvT+f6zd29MKu6LvN4Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_f3194a74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3194a746e0b91fa649eed5ccb0d43e1eb4cb87d41249fb5f38bd2740b9bbca0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 22:04:47"
  condition:
    hash.sha256(0, filesize) == "f3194a746e0b91fa649eed5ccb0d43e1eb4cb87d41249fb5f38bd2740b9bbca0"
}
```

### Sample 67: `4d79178fa6d7f062`

| Field | Value |
|---|---|
| SHA-256 | `4d79178fa6d7f0627caef122e3c29a0a95a0802ba5a050041660f4d6e11adbfd` |
| Family label | `Mirai` |
| File name | `titan.m68k` |
| File type | `elf` |
| First seen | `2026-09-08 22:03:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c88c0062570a85faa4c70ece51a5afa` |
| SHA-1 | `a48c734178ef1ba024e8bf2607615d08c09a1aa0` |
| SHA-256 | `4d79178fa6d7f0627caef122e3c29a0a95a0802ba5a050041660f4d6e11adbfd` |
| SHA3-384 | `1efbe1efb21a6c4d5920db1ed170c9a317a17f70f88f633bab64bc22d539b24a89a3fd60d1351a9b36c77341487feb37` |
| TLSH | `T1E9447C0AF802BE3DF8820A36C16F0AA53F7452E36B761E59D112A5F25F33165589BD32` |
| SSDEEP | `6144:cW4yv2JjSpl5hi/Bq3AIi8DTkyhTQOKQ02W:cW4yc4iw3AN8DTkyhTQO3S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_4d79178f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d79178fa6d7f0627caef122e3c29a0a95a0802ba5a050041660f4d6e11adbfd"
    family = "Mirai"
    file_name = "titan.m68k"
    file_type = "elf"
    first_seen = "2026-09-08 22:03:31"
  condition:
    hash.sha256(0, filesize) == "4d79178fa6d7f0627caef122e3c29a0a95a0802ba5a050041660f4d6e11adbfd"
}
```

### Sample 68: `0e4ed32d4ca30f45`

| Field | Value |
|---|---|
| SHA-256 | `0e4ed32d4ca30f45369fa17f7a8b90c0fa9f2f9ece78048c6922ccaf1853bd8d` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-08 21:56:33` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09dd70265a218b41b2f0af7b5cb1cbe4` |
| SHA-1 | `5d0d0b004ce8a9e914025db2933e4217749fc44f` |
| SHA-256 | `0e4ed32d4ca30f45369fa17f7a8b90c0fa9f2f9ece78048c6922ccaf1853bd8d` |
| SHA3-384 | `4e328077a2240087ed2b7310562f3fdbda9bfa4a5a730ffe54614cafb23b8c18eb4d0dae68c0e775a50ca9798f055fbb` |
| TLSH | `T15131A48E50240E314212CA9E7377384CF18DE1F72A9FD7D598481EE957882CCF2A6B4E` |
| SSDEEP | `12:U176/NpxBB76BdbtHvlR6s8Qr6Mf9LbdKwr6oBcQx6QDRDR1JR6J/Px6P5wc3DC4:GylsjHnz08VPd91vDCe1twmDcDk+K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_0e4ed32d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e4ed32d4ca30f45369fa17f7a8b90c0fa9f2f9ece78048c6922ccaf1853bd8d"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-08 21:56:33"
  condition:
    hash.sha256(0, filesize) == "0e4ed32d4ca30f45369fa17f7a8b90c0fa9f2f9ece78048c6922ccaf1853bd8d"
}
```

### Sample 69: `94cacfa7fcb76873`

| Field | Value |
|---|---|
| SHA-256 | `94cacfa7fcb76873c69243f5e651aa8ff7b21e4821065275e8cd6d419d49462d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-08 21:54:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1af3b66c6d0ef6d5ff24d4e03e419a6` |
| SHA-1 | `902a57cce2922ee7d1069f8cd25909a000c9d34e` |
| SHA-256 | `94cacfa7fcb76873c69243f5e651aa8ff7b21e4821065275e8cd6d419d49462d` |
| SHA3-384 | `71c78b1ae50ae0bb14e9623653a8800f21a257bbd146e0c817536ad27b501219c64ed688c2aefdfab19ae8bf7c720ae2` |
| TLSH | `T15C236C651A857C149A99C4371D7E2F0CB9AD43E6320452DE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:0VEJVIhtMk9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:KEJ2MJcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_94cacfa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94cacfa7fcb76873c69243f5e651aa8ff7b21e4821065275e8cd6d419d49462d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-08 21:54:57"
  condition:
    hash.sha256(0, filesize) == "94cacfa7fcb76873c69243f5e651aa8ff7b21e4821065275e8cd6d419d49462d"
}
```

### Sample 70: `ec0e9d8225568992`

| Field | Value |
|---|---|
| SHA-256 | `ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97` |
| Family label | `unknown` |
| File name | `ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97.bin` |
| File type | `unknown` |
| First seen | `2026-09-08 21:53:42` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b4d65345299c45047e2155414f7790f` |
| SHA-256 | `ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_ec0e9d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97"
    family = "unknown"
    file_name = "ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97.bin"
    file_type = "unknown"
    first_seen = "2026-09-08 21:53:42"
  condition:
    hash.sha256(0, filesize) == "ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97"
}
```

### Sample 71: `8865cec6bfc4cacc`

| Field | Value |
|---|---|
| SHA-256 | `8865cec6bfc4cacc0fa38975628a6c1b32f71aa6a92446ee55414e8d2f85a2e5` |
| Family label | `Mirai` |
| File name | `titan.x32` |
| File type | `elf` |
| First seen | `2026-09-08 21:51:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17851307c106e5ee54367bf1ecf9a1e7` |
| SHA-1 | `17739b43e6926b05e95c9f2150d942bdb15f97ee` |
| SHA-256 | `8865cec6bfc4cacc0fa38975628a6c1b32f71aa6a92446ee55414e8d2f85a2e5` |
| SHA3-384 | `e9e91716f867196980a72e88ab29cd14230c209bc96f0e30261dfd12c1467bf695ca501556a6068f6295e3987b79b21c` |
| TLSH | `T1B454290DF902C8B0F86291F0459FC3A17D7055F7123BAD66EF5B2AB17E322619D4722A` |
| TELFHASH | `t1017128b67e6a19e8b7d0cc0a860d5b20ee19a7773860397706f316d832f25415177c79` |
| SSDEEP | `6144:h3roKbsBRNQU7hQUyr18Ai+sRsbYg86mkyhTQOqAkq9ZXYL:Vs+WQbB86wsbYg86mkyhTQOrkC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_8865cec6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8865cec6bfc4cacc0fa38975628a6c1b32f71aa6a92446ee55414e8d2f85a2e5"
    family = "Mirai"
    file_name = "titan.x32"
    file_type = "elf"
    first_seen = "2026-09-08 21:51:32"
  condition:
    hash.sha256(0, filesize) == "8865cec6bfc4cacc0fa38975628a6c1b32f71aa6a92446ee55414e8d2f85a2e5"
}
```

### Sample 72: `f527809022eef86d`

| Field | Value |
|---|---|
| SHA-256 | `f527809022eef86d0921595f93229b802ea12fa3a140456c585f877da57fa698` |
| Family label | `Mirai` |
| File name | `20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c.elf` |
| File type | `elf` |
| First seen | `2026-09-08 21:44:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3347855aa58333ca40d5c987c59e112c` |
| SHA-1 | `421368d6433add88ee1bacba43c42f79cbb2a443` |
| SHA-256 | `f527809022eef86d0921595f93229b802ea12fa3a140456c585f877da57fa698` |
| SHA3-384 | `5daac8114cf587e0438cde6bb3e756b6e116bdd12974bb49e8e154c9732c1bfeaf0fb7f5b8775b85a2971ad3bc46fd5c` |
| TLSH | `T1CDF34C17B4C0D4FDC89AC2B44FAAE137AA32F5195134B15F67D4AF222F4EE215B1DA10` |
| TELFHASH | `t19c5187702d9a7998b2ebd366720fe539fd22081509e275f5df771ee2ca127c40d66022` |
| SSDEEP | `3072:tdPAvqRVbTqhnMjYdVk//h4oKEJdnxO9Uso2at3UVjjHgui5:tVkAVb+B7Wu+yOspjpi5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_f5278090
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f527809022eef86d0921595f93229b802ea12fa3a140456c585f877da57fa698"
    family = "Mirai"
    file_name = "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:44:18"
  condition:
    hash.sha256(0, filesize) == "f527809022eef86d0921595f93229b802ea12fa3a140456c585f877da57fa698"
}
```

### Sample 73: `20627e7bbf0bd28d`

| Field | Value |
|---|---|
| SHA-256 | `20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c` |
| Family label | `Mirai` |
| File name | `20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c.elf` |
| File type | `elf` |
| First seen | `2026-09-08 21:43:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7509303ed3162e62d91e105f4547ca67` |
| SHA-1 | `cba5df082150935a4118d8d16578390536704e58` |
| SHA-256 | `20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c` |
| SHA3-384 | `78e8c372dcf270a0e69d82e037ff58686b253594cf3cf05690310110725250350b8bc6583995bfc098ec8fb99f404793` |
| TLSH | `T12853F11B836ADF78C6B1E831A40F7C94A6B6ED195202174B118A35DCC8B27D7BE2C371` |
| SSDEEP | `1536:ehejrFZqD9EC/WUM+F5hY4lPUY/CSWHT+dL+V:DrFAD9UJ+F5B/8+hC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_20627e7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c"
    family = "Mirai"
    file_name = "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:43:44"
  condition:
    hash.sha256(0, filesize) == "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c"
}
```

### Sample 74: `f601cde9845b729d`

| Field | Value |
|---|---|
| SHA-256 | `f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7` |
| Family label | `unknown` |
| File name | `f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7.bin` |
| File type | `exe` |
| First seen | `2026-09-08 21:43:34` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c31991f6adba0cd505e1e8f59cdf0b9d` |
| SHA-1 | `9a90dfde0b02cb410c7f79f6529ad2aade4e1969` |
| SHA-256 | `f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7` |
| SHA3-384 | `c81c1f0d8fa54f56827f0c123b551c5aa7a634102c26ff666bdb682c9c722b06bb6918690548cac72db8856684a4965d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D926AE076C88946AC1A59B35886A11527B60FC5CD73233EB2F50F7B82F72BC05D7AB49` |
| SSDEEP | `49152:CTQ9jBwm0Vh0vLf/mZZETIz3q83ISp8z8mUFQc32PfwGfysLwYMIawQwYu+:CS+h8/ITqiIoVywVcwYM6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_f601cde9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7"
    family = "unknown"
    file_name = "f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7.bin"
    file_type = "exe"
    first_seen = "2026-09-08 21:43:34"
  condition:
    hash.sha256(0, filesize) == "f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7"
}
```

### Sample 75: `f1142e07e25d8178`

| Field | Value |
|---|---|
| SHA-256 | `f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3` |
| Family label | `unknown` |
| File name | `f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3.bin` |
| File type | `exe` |
| First seen | `2026-09-08 21:43:33` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54eb3cae1e8ec4c0e164ea9e24ef5af2` |
| SHA-1 | `56e119c62e3631015420445dd488496663a88d35` |
| SHA-256 | `f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3` |
| SHA3-384 | `dd98e3f9e97d537013d69b635f21e2ba12c8b55c6312aaf483f8b1322829b4b4182d1ca6c15d29e96fd8f078c5e2fa2c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17326AE07ACA560AAC2DA9739847A16107B64BC4D8B3133E72F50E7B42E737C05E7AF15` |
| SSDEEP | `49152:bEC/LsD10OTSJfizBSXsLF2mTrTrEit60ynoTngzqvIZAmOywQprB0:bn+OJizgsR5D1tPyGn76w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_f1142e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3"
    family = "unknown"
    file_name = "f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3.bin"
    file_type = "exe"
    first_seen = "2026-09-08 21:43:33"
  condition:
    hash.sha256(0, filesize) == "f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3"
}
```

### Sample 76: `65dd73ff6820fdc0`

| Field | Value |
|---|---|
| SHA-256 | `65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4` |
| Family label | `Mirai` |
| File name | `65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4.elf` |
| File type | `elf` |
| First seen | `2026-09-08 21:39:24` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3edfced2e21761e60d6271c235f39f58` |
| SHA-1 | `371584688b216dc536c756a444900fc38a266b89` |
| SHA-256 | `65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4` |
| SHA3-384 | `50c3b4888af0ef8c172b32b6b73fa3ad4985e920006894670cc4a4faa0ef985ca5afac5b8e4aff5920c94ebbc3491cd5` |
| TLSH | `T1E7158E5AF1B330FCC56BC034476BDB726931F46911216E7B12C4DA392D92EB02729FA6` |
| TELFHASH | `t1c99179704af624b1629bd901b322f1fa9eb62c2a51ed35b52736add4ef05f801cb6413` |
| SSDEEP | `12288:Q42Mcyj/OK4HYPdbYLcm1wlrdy4ZRTdJBOmy3L8GSFE5k:Q42MceGK4HYPdScm1wlrEMRTh8xS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_65dd73ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4"
    family = "Mirai"
    file_name = "65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:39:24"
  condition:
    hash.sha256(0, filesize) == "65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4"
}
```

### Sample 77: `06710dd73fee4a51`

| Field | Value |
|---|---|
| SHA-256 | `06710dd73fee4a517b98dac1823e091bb3defdef400d7a20c65ea78eb85c0f52` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-08 21:34:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `883871dd31d2d7fe20cc5b7e2df2a982` |
| SHA-1 | `703e2c761e18262eea572d4ea462b041a3dd8aa1` |
| SHA-256 | `06710dd73fee4a517b98dac1823e091bb3defdef400d7a20c65ea78eb85c0f52` |
| SHA3-384 | `9e932481be0bc434faa1ac1d80bd50c5bbf9e638b3d5e4bf3d6c7cec50dc5f6ab2dadc8b488d4d59bd176b40d8b5fed4` |
| TLSH | `T1C9A34B227D721D2BC4D4A47962F70335F2BB878A217C8A1A7E610E8CBF756407257BE4` |
| SSDEEP | `1536:QtEUXWrES+aThR01EBhgM1pgMu8FqtcUL75YzR03x2tXhNX54MXNPc:KXZkPg+po2+V0PbO0N0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_06710dd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06710dd73fee4a517b98dac1823e091bb3defdef400d7a20c65ea78eb85c0f52"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-08 21:34:32"
  condition:
    hash.sha256(0, filesize) == "06710dd73fee4a517b98dac1823e091bb3defdef400d7a20c65ea78eb85c0f52"
}
```

### Sample 78: `b882d7626ff89aa5`

| Field | Value |
|---|---|
| SHA-256 | `b882d7626ff89aa52514fdb06a9333db386e98b31937d0184d65c8ba70474eed` |
| Family label | `Mirai` |
| File name | `titan.ppc440` |
| File type | `elf` |
| First seen | `2026-09-08 21:31:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f7329ff1f7dc9455a2566e118553759` |
| SHA-1 | `7ba34390b6afc34da733fa8ae04b5aadd9d36a6f` |
| SHA-256 | `b882d7626ff89aa52514fdb06a9333db386e98b31937d0184d65c8ba70474eed` |
| SHA3-384 | `5e7b27f27b12bbc749041216598c2fd6a7eaf0cf9aeec5a47b6b59cd69d7d87472c5fb796675190f72ebdc009689ed38` |
| TLSH | `T19F645C02FB048932FD420EB09A7F07E5BBB141C316B9A909550F57B11B3367AE5D37AA` |
| SSDEEP | `6144:NZsjxJYpFDwwScXLvrItqapFCeVdwGz83kyhTQOmsL1Q:NiYrNjrg83kyhTQOxL+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_b882d762
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b882d7626ff89aa52514fdb06a9333db386e98b31937d0184d65c8ba70474eed"
    family = "Mirai"
    file_name = "titan.ppc440"
    file_type = "elf"
    first_seen = "2026-09-08 21:31:00"
  condition:
    hash.sha256(0, filesize) == "b882d7626ff89aa52514fdb06a9333db386e98b31937d0184d65c8ba70474eed"
}
```

### Sample 79: `7fb8a78604d0f7df`

| Field | Value |
|---|---|
| SHA-256 | `7fb8a78604d0f7df0734cde30c48babf079926abcba3c4725b68b43c872c8f0b` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-08 21:30:59` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9166b23499800c193bd6b8e69224844c` |
| SHA-256 | `7fb8a78604d0f7df0734cde30c48babf079926abcba3c4725b68b43c872c8f0b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_7fb8a786
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fb8a78604d0f7df0734cde30c48babf079926abcba3c4725b68b43c872c8f0b"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-08 21:30:59"
  condition:
    hash.sha256(0, filesize) == "7fb8a78604d0f7df0734cde30c48babf079926abcba3c4725b68b43c872c8f0b"
}
```

### Sample 80: `d49b6364096bad20`

| Field | Value |
|---|---|
| SHA-256 | `d49b6364096bad20e30d3c2be46c9aac136626f26f78ba0dc19ced6f897b073e` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-08 21:27:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b0f241254df6369eb212877606beb20` |
| SHA-1 | `79bcd1bf0a7889812806aaa59ae953ac728d9c9d` |
| SHA-256 | `d49b6364096bad20e30d3c2be46c9aac136626f26f78ba0dc19ced6f897b073e` |
| SHA3-384 | `71dcc09570e27e0456f50f7dc2fcc4098734862a0a821bdab92b54a12d5b76f7bb351782b25fa1efa64f313f28c7cf2f` |
| TLSH | `T1CE235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCF3CF68C4A6AD9109B1D` |
| SSDEEP | `768:G+M9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:G+hcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_d49b6364
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d49b6364096bad20e30d3c2be46c9aac136626f26f78ba0dc19ced6f897b073e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-08 21:27:32"
  condition:
    hash.sha256(0, filesize) == "d49b6364096bad20e30d3c2be46c9aac136626f26f78ba0dc19ced6f897b073e"
}
```

### Sample 81: `25d775826462960f`

| Field | Value |
|---|---|
| SHA-256 | `25d775826462960f3e9aac0a58c5317f69809f2a403c09a242bbec88e0792069` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-08 21:27:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3ecda7ee789a7a40c6a7f8b3b8733da` |
| SHA-1 | `124b642590786bb938da6311fe8eb633b437fd31` |
| SHA-256 | `25d775826462960f3e9aac0a58c5317f69809f2a403c09a242bbec88e0792069` |
| SHA3-384 | `be398d330bca96d14de30cead87e5bdaf88a4db20a108de55ce41e233c2c461e2d12ebd0a13ba8209ca728ba59fbf486` |
| TLSH | `T19BD35973C8256F58C568D5B5B0348F7D2B63A91182871FBE19A7C6788083DCCF64A7B8` |
| SSDEEP | `1536:nqAeO63ssg5z8PyC4HKTgetTj/7LSFKJjUWJLVPRYs/v/aAYx:nqAgss8zbeTR7LSkFUW9Vj/XaAY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_25d77582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d775826462960f3e9aac0a58c5317f69809f2a403c09a242bbec88e0792069"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-08 21:27:31"
  condition:
    hash.sha256(0, filesize) == "25d775826462960f3e9aac0a58c5317f69809f2a403c09a242bbec88e0792069"
}
```

### Sample 82: `1476885ceabb54b2`

| Field | Value |
|---|---|
| SHA-256 | `1476885ceabb54b25f302d2fa363a87b3b11a4616328fa0844bb9e7a160d5946` |
| Family label | `Mirai` |
| File name | `titan.sh4` |
| File type | `elf` |
| First seen | `2026-09-08 21:25:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6946a924cd0203ed19b02134d393354f` |
| SHA-1 | `cbbe184e2d8045ebb6e7d6a67ba9e3697067e2f0` |
| SHA-256 | `1476885ceabb54b25f302d2fa363a87b3b11a4616328fa0844bb9e7a160d5946` |
| SHA3-384 | `fe38f3ea18c96f313a28dc8cfdd5322452c5d6758e9b961053c30a5730a0d642ef0b15ee0d5864997cd402e2edff6092` |
| TLSH | `T1B8445A5AF462CD65F54209F498EEC2B03F2096E3273B2D50E5BB42F41B63469B847B72` |
| SSDEEP | `3072:cjwywiGCFa33/TBKoLV0dPV4a4YV8h/RxkG7hTQLqmWUqU:Sw1CFaLB9LVWd4a4Y85kyhTQOmWUq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_1476885c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1476885ceabb54b25f302d2fa363a87b3b11a4616328fa0844bb9e7a160d5946"
    family = "Mirai"
    file_name = "titan.sh4"
    file_type = "elf"
    first_seen = "2026-09-08 21:25:58"
  condition:
    hash.sha256(0, filesize) == "1476885ceabb54b25f302d2fa363a87b3b11a4616328fa0844bb9e7a160d5946"
}
```

### Sample 83: `57a8965812e8f5bb`

| Field | Value |
|---|---|
| SHA-256 | `57a8965812e8f5bb8f9f0abff20e77333c8072f530adc970ccabbaa9ccf6e1dd` |
| Family label | `Mirai` |
| File name | `titan.arm7` |
| File type | `elf` |
| First seen | `2026-09-08 21:25:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e79cfce0ac18fa17646ac5d4983b108b` |
| SHA-1 | `3659a9229bf51fb8d30bc9b6d6ebda768ec35397` |
| SHA-256 | `57a8965812e8f5bb8f9f0abff20e77333c8072f530adc970ccabbaa9ccf6e1dd` |
| SHA3-384 | `28e1b76e6bd7037e8e10fe973417b14b6d7b557c60b2ebbae32bfeb60ee6682383546c8e4027e919274e24243979e326` |
| TLSH | `T11444084AFC41CE61F98106B5FB5E82D83B2303FBC7FE750199050BB42B6762A4A77952` |
| TELFHASH | `t1ef41dfa7fba82a9c5be5c290c2999039e7b4358d570531528e0da75f8e82ec1712d823` |
| SSDEEP | `6144:c04ZsN2VnDf/l5zWsyNCKPJgJpK8PRqlsw8nkyhTQOmw/Uqj:cjZs2f/PzWsy/JgJ9PRY8nkyhTQOF/U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_57a89658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a8965812e8f5bb8f9f0abff20e77333c8072f530adc970ccabbaa9ccf6e1dd"
    family = "Mirai"
    file_name = "titan.arm7"
    file_type = "elf"
    first_seen = "2026-09-08 21:25:57"
  condition:
    hash.sha256(0, filesize) == "57a8965812e8f5bb8f9f0abff20e77333c8072f530adc970ccabbaa9ccf6e1dd"
}
```

### Sample 84: `57130207e60dc059`

| Field | Value |
|---|---|
| SHA-256 | `57130207e60dc0596100e86cc67e288dd092fd3ffaeb230f8a1fd975797b56d0` |
| Family label | `Mirai` |
| File name | `titan.mips` |
| File type | `elf` |
| First seen | `2026-09-08 21:24:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bace0b81444df5e4d41d42ffd1d23cb0` |
| SHA-1 | `0b8f3763e8eef5c02bace7dd8ef2862c66afdc09` |
| SHA-256 | `57130207e60dc0596100e86cc67e288dd092fd3ffaeb230f8a1fd975797b56d0` |
| SHA3-384 | `a81f5b2b20cefd55432efd77cf1fd835e81a2b24b95f43f73f9f870ce1dca52510a17c44eb43057105b32d33dc97fb06` |
| TLSH | `T179742A167A21CF70F615C1314ABBC9917EE411D32BF14895A32DCB683F3225A684BEF6` |
| TELFHASH | `t1a831b41c497823f0e7755c5d56edfb7ae5a131db2a222c338e10e9a9ab6dc824d10c1c` |
| SSDEEP | `6144:8Cfu+IkN0cg68Mj5jsZrHFSZt9NQJlmIen/Wi8/8fkyhTQOm4Sn:b4VILjQ2Rn/Wh8fkyhTQOPSn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_57130207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57130207e60dc0596100e86cc67e288dd092fd3ffaeb230f8a1fd975797b56d0"
    family = "Mirai"
    file_name = "titan.mips"
    file_type = "elf"
    first_seen = "2026-09-08 21:24:29"
  condition:
    hash.sha256(0, filesize) == "57130207e60dc0596100e86cc67e288dd092fd3ffaeb230f8a1fd975797b56d0"
}
```

### Sample 85: `c9b0003da146ddc5`

| Field | Value |
|---|---|
| SHA-256 | `c9b0003da146ddc53fc6d4b77e91942b1298d9bd159a2a02dc2fa4ef20c7148f` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-09-08 21:20:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90b5985f096aad09ad26e81059ec0750` |
| SHA-1 | `0fe59d07e87f75b900e4eb9dafada0229f8e9ed4` |
| SHA-256 | `c9b0003da146ddc53fc6d4b77e91942b1298d9bd159a2a02dc2fa4ef20c7148f` |
| SHA3-384 | `9af00d4eccfa8ad8141dd7ad8097c1dba5fa6343e701c49d7ce451ebe561a6b27dfb649c88ae30a29ff347767fe3e2b5` |
| TLSH | `T1A3F33B06B31C0A47D1633EF43B3F27E193EF9A5120E4E644255FAA899271E331586EDE` |
| SSDEEP | `3072:hLydplNUEClBN1plBN1FDz6xdoOcpxmM1YJOx+zPgoPW:hLLFntxmM1YEkzP9W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_c9b0003d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9b0003da146ddc53fc6d4b77e91942b1298d9bd159a2a02dc2fa4ef20c7148f"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-08 21:20:33"
  condition:
    hash.sha256(0, filesize) == "c9b0003da146ddc53fc6d4b77e91942b1298d9bd159a2a02dc2fa4ef20c7148f"
}
```

### Sample 86: `c55604b959e8c985`

| Field | Value |
|---|---|
| SHA-256 | `c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690` |
| Family label | `Mirai` |
| File name | `c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690.elf` |
| File type | `elf` |
| First seen | `2026-09-08 21:20:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e46ec6be9b706648c313f54d48e872e9` |
| SHA-1 | `0cc35c1365ff4e0fd5f77f35e7149ac94451a052` |
| SHA-256 | `c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690` |
| SHA3-384 | `cf76dd282ab916d7c15e28abcb7b4573cf92f20fbbb023d44ea91aabe0047cc148c4fa13f7f62e84e86996d52ebbfeb8` |
| TLSH | `T16DC32901E5908767C2D2137AF79F429D37336F68979B33219A24BBF42B8179D1E39221` |
| TELFHASH | `t1ad212d5262fe8a286bf35924ec7c43b115a12a2362857e70bf1ec5c4443b047b865daf` |
| SSDEEP | `3072:zcP+wadgzyj+AmM2aTXOwszFib3l3yQRb6EPvqUYmcQY47aGgp:zD+AH2aTGibV3yrmqUYmcQY4+Ggp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_c55604b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690"
    family = "Mirai"
    file_name = "c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:20:02"
  condition:
    hash.sha256(0, filesize) == "c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690"
}
```

### Sample 87: `56ee76316c9c8d95`

| Field | Value |
|---|---|
| SHA-256 | `56ee76316c9c8d9561cf318fb1d1439d069c7fe9da91214ce976e8c3beb8cd4b` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-09-08 21:19:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b73139c6103d3c771ccf37100f4eb798` |
| SHA-1 | `ec65e4c353059d49c6ea3c0ef53f9c4fba9bfc69` |
| SHA-256 | `56ee76316c9c8d9561cf318fb1d1439d069c7fe9da91214ce976e8c3beb8cd4b` |
| SHA3-384 | `fe656b6672b3db7597b41b8e95086f5697d35f89b8d65e774226b6b5c612c86206104feab1f0ebabd916bf3a5cf6a09f` |
| TLSH | `T1D943F126F26E0B16FE7BEF721E1BC2C233C15E693C4726E910E46E568B56E30395149C` |
| SSDEEP | `1536:UePC1bgW0E2ZCO15rXQ/54dRgaAUIUAXnjz69JxPuo3OOUC4u+qgw097:Ue61cW0rV1e8RhAUIFXmP/Oa4u+qgwi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_56ee7631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56ee76316c9c8d9561cf318fb1d1439d069c7fe9da91214ce976e8c3beb8cd4b"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-08 21:19:54"
  condition:
    hash.sha256(0, filesize) == "56ee76316c9c8d9561cf318fb1d1439d069c7fe9da91214ce976e8c3beb8cd4b"
}
```

### Sample 88: `8127b15b21a33733`

| Field | Value |
|---|---|
| SHA-256 | `8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e` |
| Family label | `Mirai` |
| File name | `8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e.elf` |
| File type | `elf` |
| First seen | `2026-09-08 21:19:38` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `feae24bdf86c618b9d841bd1b46dff3a` |
| SHA-1 | `e6bfe2c97f7ae206996d13cf030acab012f9a4db` |
| SHA-256 | `8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e` |
| SHA3-384 | `cd776032083d11639107310a15be4f0200a708c66df265744edd5641c215d920e0277a4b9bc186df37a4856a0268cd00` |
| TLSH | `T18EB33B41FD408767C2D227B6F78E479D3B365A6497DB331169397EB42BC1B882E39220` |
| TELFHASH | `t17311239221ff89282bf24928ac7c47b11591211323917e70ef1ec5d44437046f965d9f` |
| SSDEEP | `3072:Xqd1uE0YlkRt5RiUlaYS6KV5Vyuzw5dm7ZTQOh21JXwQA:RiUlGFvVyu4m7ZTQOhMJXwQA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_8127b15b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e"
    family = "Mirai"
    file_name = "8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:19:38"
  condition:
    hash.sha256(0, filesize) == "8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e"
}
```

### Sample 89: `474187ebbc6b0dce`

| Field | Value |
|---|---|
| SHA-256 | `474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11` |
| Family label | `ConnectWise` |
| File name | `474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11.exe` |
| File type | `exe` |
| First seen | `2026-09-08 21:18:47` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4e034ea1611529957c22092a8a5d2d9` |
| SHA-1 | `e1b712547c0cb095e5ffc4aebe2f5ebd702e3dd9` |
| SHA-256 | `474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11` |
| SHA3-384 | `535ec7a3f11de0e7bf0b73e837b5e22ea9b1d1753b9b587eeb521c12690af463dab3c467291d3b1b845636841e07f4ea` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1EDD61211B3E691B5E0BF0638D87A62666631BC128751C7AF6794BE792D327C08E31373` |
| SSDEEP | `98304:C3GF0s6efPzMn1Giy8E1PqhyG6ztZNK9aNGrMn1Giy8E1PqhAMn1Giy8E1Pqh1Ms:kGufefPyZWiEz3I96bZWijZWi0ZWiw` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_089_474187eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11"
    family = "ConnectWise"
    file_name = "474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11.exe"
    file_type = "exe"
    first_seen = "2026-09-08 21:18:47"
  condition:
    hash.sha256(0, filesize) == "474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11"
}
```

### Sample 90: `78c765978a0c2683`

| Field | Value |
|---|---|
| SHA-256 | `78c765978a0c2683eddafbbcc6e7896bf7172d63a936c602457034064016f3a5` |
| Family label | `Mirai` |
| File name | `telnet` |
| File type | `elf` |
| First seen | `2026-09-08 21:16:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c6e46e0928fde6149de8951842568c1` |
| SHA-1 | `f6470b1f94778310ec0b8a3e8c111af3b1f65a6d` |
| SHA-256 | `78c765978a0c2683eddafbbcc6e7896bf7172d63a936c602457034064016f3a5` |
| SHA3-384 | `05e52e1debaeea62e02dc105fc4d211bb4e28fb97a7db96388a83ed1e14825383bd968543821f0a56a1b79145e64fd63` |
| TLSH | `T1F9A32C80FD458767C3C227B7F78E479D3B355A649BDB331165386EF42B81B982E29220` |
| TELFHASH | `t17311239221ff89282bf24928ac7c47b11591211323917e70ef1ec5d44437046f965d9f` |
| SSDEEP | `3072:U9d1uE0Ylk0t58SU8toJ2ei5RUyZB0BmQwiQmvvhMXWyA:6hU8Cp4RUyj4mQwiQmv5MXWyA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_78c76597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78c765978a0c2683eddafbbcc6e7896bf7172d63a936c602457034064016f3a5"
    family = "Mirai"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-09-08 21:16:55"
  condition:
    hash.sha256(0, filesize) == "78c765978a0c2683eddafbbcc6e7896bf7172d63a936c602457034064016f3a5"
}
```

### Sample 91: `9ccc4db28c8da295`

| Field | Value |
|---|---|
| SHA-256 | `9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae` |
| Family label | `Mirai` |
| File name | `titan.arm5` |
| File type | `elf` |
| First seen | `2026-09-08 21:15:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87fb28c7a73c9426594cba2dc9a14e30` |
| SHA-1 | `fb14206f810d76c51c3c8b64efab6215e4778110` |
| SHA-256 | `9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae` |
| SHA3-384 | `9677c8992eb9e462d9c7746aca435717d1acef1131ae86bed317e6cb6266dd154d20169ca512118dc43653abf3468c22` |
| TLSH | `T1D044085AF841CE21F9D116F5FA9E42D83B2303FBD7FE740699050B742BA785A0E27912` |
| TELFHASH | `t1dfe0c286e2941fa8b3d14b5873e42657eee13554db002896491d741ff9d2bc3b01a832` |
| SSDEEP | `6144:ww+W0lgqsEFx+gduhCj9LRAPJ3X9iPO5QeL7NQsRC80kyhTQOmw/UqK0:w9B9LRAPJ3025QONa80kyhTQOF/U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_9ccc4db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae"
    family = "Mirai"
    file_name = "titan.arm5"
    file_type = "elf"
    first_seen = "2026-09-08 21:15:29"
  condition:
    hash.sha256(0, filesize) == "9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae"
}
```

### Sample 92: `b4b9fa7c5472840a`

| Field | Value |
|---|---|
| SHA-256 | `b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329` |
| Family label | `ConnectWise` |
| File name | `b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329.msi` |
| File type | `msi` |
| First seen | `2026-09-08 21:08:54` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `162e5f309e7c5a14127559d1bf6b6a99` |
| SHA-1 | `22699607e330f5d824da769d27cb0f82a52f3f71` |
| SHA-256 | `b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329` |
| SHA3-384 | `3339efecb74979e4b2a0d1e894407c0214a1e0cc80764cc41cfd683f26f10bb7e0f7eea3e651506fc5e92410392e4a6e` |
| TLSH | `T18DE6230573F8A109F1B32A3AED3955F19C7B7C228D62D15E1658364E1AB0EC19AB3733` |
| SSDEEP | `393216:EmkEdQ03NldumkEd8mkEd8mkEdZmkEdvmkEdjmkEd:ME2cxCEqEGExErEfE` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_092_b4b9fa7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329"
    family = "ConnectWise"
    file_name = "b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329.msi"
    file_type = "msi"
    first_seen = "2026-09-08 21:08:54"
  condition:
    hash.sha256(0, filesize) == "b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329"
}
```

### Sample 93: `a3d1af638d5f16e7`

| Field | Value |
|---|---|
| SHA-256 | `a3d1af638d5f16e7e2aa9aea53fe2da960f4068e628ff9c6a5cf9a696a198cb1` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-08 21:04:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05d6c116f6c38ab44644e3287e18931c` |
| SHA-1 | `7dfc896b1042b2d38d1143c071bc533e00cc95dd` |
| SHA-256 | `a3d1af638d5f16e7e2aa9aea53fe2da960f4068e628ff9c6a5cf9a696a198cb1` |
| SHA3-384 | `fe0e2d23bf41c4ff502534f5825c97f8d6f6f84a135de3d56e227c6721f65b005e1b55ed81d511d5ae6ff7c8f95cc503` |
| TLSH | `T1BFC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:58vCB+25j6es8R49FYpMSUpi+20qUpi+20YQX:58l25JOd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_a3d1af63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3d1af638d5f16e7e2aa9aea53fe2da960f4068e628ff9c6a5cf9a696a198cb1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-08 21:04:52"
  condition:
    hash.sha256(0, filesize) == "a3d1af638d5f16e7e2aa9aea53fe2da960f4068e628ff9c6a5cf9a696a198cb1"
}
```

### Sample 94: `97f2d7035e4a4e3d`

| Field | Value |
|---|---|
| SHA-256 | `97f2d7035e4a4e3d1d832e091cd229e7bec93525e7e3c22bed7dd43063181674` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-08 21:04:51` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bff50ef5aeebe48b67bd7045c4fa583a` |
| SHA-256 | `97f2d7035e4a4e3d1d832e091cd229e7bec93525e7e3c22bed7dd43063181674` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_97f2d703
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97f2d7035e4a4e3d1d832e091cd229e7bec93525e7e3c22bed7dd43063181674"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-08 21:04:51"
  condition:
    hash.sha256(0, filesize) == "97f2d7035e4a4e3d1d832e091cd229e7bec93525e7e3c22bed7dd43063181674"
}
```

### Sample 95: `0d85349b8f1c736d`

| Field | Value |
|---|---|
| SHA-256 | `0d85349b8f1c736d103ac566fbf28b895e0565c545bece7633ff19778f40408b` |
| Family label | `Mirai` |
| File name | `7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027.elf` |
| File type | `elf` |
| First seen | `2026-09-08 20:54:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ed846195f72a7127631a375ec0b0f41` |
| SHA-1 | `03b772f20f5661ea53f82edbced90813ea415576` |
| SHA-256 | `0d85349b8f1c736d103ac566fbf28b895e0565c545bece7633ff19778f40408b` |
| SHA3-384 | `daf2c0d4beed404f533f4acea6a3e68d8c143a8d6f5b98124a93b533913de3c697d10ee1fe589ab65d883a40f45914f4` |
| TLSH | `T1D6B35CC5F683D4F6EC6255756027F7374B33D839503ADA87D3ADAE32AC226018A1A71C` |
| TELFHASH | `t1975107fb6a760ce8b7c0a805d31e6f926d1dd73b156036e305f3452432a6dd142bac39` |
| SSDEEP | `1536:udlPRrwXZaqgLKiTPtJNDPDoAcy/QQF7D2Vhu9vHX5EO5SsXhsVMb6ZTJD:A5r7jntjDMyODoHpQsRFKTp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_0d85349b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d85349b8f1c736d103ac566fbf28b895e0565c545bece7633ff19778f40408b"
    family = "Mirai"
    file_name = "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:54:17"
  condition:
    hash.sha256(0, filesize) == "0d85349b8f1c736d103ac566fbf28b895e0565c545bece7633ff19778f40408b"
}
```

### Sample 96: `7b93ebd36c707e33`

| Field | Value |
|---|---|
| SHA-256 | `7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027` |
| Family label | `Mirai` |
| File name | `7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027.elf` |
| File type | `elf` |
| First seen | `2026-09-08 20:53:49` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa093be2ef23ab1d3851df8c1bc26fe4` |
| SHA-1 | `305752c6782b809be8080d0ad02c61e7531c88f6` |
| SHA-256 | `7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027` |
| SHA3-384 | `60637be66254aac97ac56f978e39536c8b563bf0e9886066709e4bea71662b7cfb6c2c06f01a4196d86a52e331dc31dd` |
| TLSH | `T10433F179C5D61106E937303A3C59380AADA2EA3FEB44D1D58DE0F0B7DEB1AD2175C608` |
| SSDEEP | `1536:v86r5lBX7b5N1szIIZoIJqIhYMajleO0Wfnouy8jn:Eg/BLb98oIJqI+hoO0Ooutjn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_7b93ebd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027"
    family = "Mirai"
    file_name = "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:53:49"
  condition:
    hash.sha256(0, filesize) == "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027"
}
```

### Sample 97: `073bc6f44e0f2c23`

| Field | Value |
|---|---|
| SHA-256 | `073bc6f44e0f2c23183f87f73e413e74e21d185f2974183d9b5ca1cb8bd3e1d7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-08 20:48:45` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac7fe584292a2a1061310bd694948551` |
| SHA-1 | `d169a040985fd55840fa449bf5012dff81e0144f` |
| SHA-256 | `073bc6f44e0f2c23183f87f73e413e74e21d185f2974183d9b5ca1cb8bd3e1d7` |
| SHA3-384 | `27b7a46faeb148278cb0576257a90c7cfc8b92a97f5dc2841f5e82717df7a7afa8ac6cc641d820ffead625724bfb4751` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1F5E6C003EC5548E8C0EBD13285A38513BB21BC895B2577D71BA0B229AF72BD06F7579C` |
| SSDEEP | `393216:OJ+8dSYRG13q8kLgcUKgu+jeoZxA+aJ6y6Un:OJrG1LuGfvvoD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_073bc6f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "073bc6f44e0f2c23183f87f73e413e74e21d185f2974183d9b5ca1cb8bd3e1d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 20:48:45"
  condition:
    hash.sha256(0, filesize) == "073bc6f44e0f2c23183f87f73e413e74e21d185f2974183d9b5ca1cb8bd3e1d7"
}
```

### Sample 98: `4bccec3aec8dbdda`

| Field | Value |
|---|---|
| SHA-256 | `4bccec3aec8dbdda25d35e893921a5f5fcf02ed2145e0c34841a529654621919` |
| Family label | `Mirai` |
| File name | `titan.arm7` |
| File type | `elf` |
| First seen | `2026-09-08 20:32:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `436138c2c9bfff63623d7107e08840b5` |
| SHA-1 | `05d63029519ee08906520704f363f4022e0165b7` |
| SHA-256 | `4bccec3aec8dbdda25d35e893921a5f5fcf02ed2145e0c34841a529654621919` |
| SHA3-384 | `47ef60fe838386a63f91697aabefed5b09a33d6af9ce9d85524578037bb7c365dd92b47b5025f9808b03b867a62770b1` |
| TLSH | `T16244184AFC41CA61F98106B5FB5E82D83B2303FBC7FE75019C064BB42BA751A4A77952` |
| TELFHASH | `t18541bf66fb9c1a9c6be182d483d99125cfe4328a57442546ce0ceb5f8d43ec2b42d833` |
| SSDEEP | `6144:XQbNkgJTxfkxsuvTs5PLpmw/uiQwxc6cW8NkyhTQOmw/Uqe:X0NkyxfkxsuvTsnmw+wxl8NkyhTQOF/U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_4bccec3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bccec3aec8dbdda25d35e893921a5f5fcf02ed2145e0c34841a529654621919"
    family = "Mirai"
    file_name = "titan.arm7"
    file_type = "elf"
    first_seen = "2026-09-08 20:32:55"
  condition:
    hash.sha256(0, filesize) == "4bccec3aec8dbdda25d35e893921a5f5fcf02ed2145e0c34841a529654621919"
}
```

### Sample 99: `2a6a7d52100618b5`

| Field | Value |
|---|---|
| SHA-256 | `2a6a7d52100618b5a38a8ec50c425d8137cfe1f33d86d526f474ed942f871e71` |
| Family label | `Mirai` |
| File name | `8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478.elf` |
| File type | `elf` |
| First seen | `2026-09-08 20:29:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cad3a1ad1a214d81db6dcd9239cdf19e` |
| SHA-1 | `8040ce3ad50243f9caee2a8570054079e30db63a` |
| SHA-256 | `2a6a7d52100618b5a38a8ec50c425d8137cfe1f33d86d526f474ed942f871e71` |
| SHA3-384 | `0870fcefd9386373bdead6d1893528c85d9e6c5b75677349d2d83126e9a088073433ac69e36050cf6513ddc526c31f85` |
| TLSH | `T16F834B8DF783F4F5EC061A70102BF37E96759D121064DD6BDBA4FA62AE32713920A61C` |
| TELFHASH | `t10431a7f91fa90cd4b7d06806c14eaf914e3ae67f65103aa34672622433dfe53516ac78` |
| SSDEEP | `1536:SFcqL0cnNny3w94EGhRGj4PrXPqVOpRLA9KxjGA3:SKqLXUgADGjwrXPq9KoA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_2a6a7d52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a6a7d52100618b5a38a8ec50c425d8137cfe1f33d86d526f474ed942f871e71"
    family = "Mirai"
    file_name = "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:29:25"
  condition:
    hash.sha256(0, filesize) == "2a6a7d52100618b5a38a8ec50c425d8137cfe1f33d86d526f474ed942f871e71"
}
```

### Sample 100: `8876d082a455b569`

| Field | Value |
|---|---|
| SHA-256 | `8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478` |
| Family label | `Mirai` |
| File name | `8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478.elf` |
| File type | `elf` |
| First seen | `2026-09-08 20:29:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b55eb291a402b5e715e854aed71663d` |
| SHA-1 | `7b26a8ef8898a93993a97c542efb66c745a116d8` |
| SHA-256 | `8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478` |
| SHA3-384 | `a8fe40ce515e9b142bbbb4821eaa839563f88631a15de1bf7a4bd193164408ca64dede3030d8e62379219ca268e13eaf` |
| TLSH | `T1DB13F15AC17A5166C0CBB038780FF1F55C14DA8A30D9E4E2FDC8687A5162D46BFEE0E2` |
| SSDEEP | `768:A2m656tBMVFG796QofJPdHsr81q5FBKhaXYwf1RcsCAuJyoGYLrnbcuyD7Un/2V:46ct1796Q+ZdkllKPwPcZQUrnouy8+V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_8876d082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478"
    family = "Mirai"
    file_name = "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:29:14"
  condition:
    hash.sha256(0, filesize) == "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478"
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
 * Generated: 2026-09-09T04:51:03.000345+00:00
 */

rule MalwareBazaar_unknown_001_05619f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05619f43a3fc34d50709f784dcb7f7c47c88d0c32d5b6d8d0c0e720d68de1a81"
    family = "unknown"
    file_name = "所得税の確定申告に係る納税通知書.zip"
    file_type = "zip"
    first_seen = "2026-09-09 04:33:13"
  condition:
    hash.sha256(0, filesize) == "05619f43a3fc34d50709f784dcb7f7c47c88d0c32d5b6d8d0c0e720d68de1a81"
}

rule MalwareBazaar_unknown_002_f45af05d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f45af05d0c72ce3125c41cfd4b87b428f9466be5137ac41ce4daf84b12a06eeb"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-09 04:27:51"
  condition:
    hash.sha256(0, filesize) == "f45af05d0c72ce3125c41cfd4b87b428f9466be5137ac41ce4daf84b12a06eeb"
}

rule MalwareBazaar_unknown_003_4c4543b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c4543b1963b22fb4bdd039558c6f8ea913ada5c61f1b36637318804dec9f322"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-09 04:21:31"
  condition:
    hash.sha256(0, filesize) == "4c4543b1963b22fb4bdd039558c6f8ea913ada5c61f1b36637318804dec9f322"
}

rule MalwareBazaar_VShell_004_7627323d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a"
    family = "VShell"
    file_name = "7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a.exe"
    file_type = "exe"
    first_seen = "2026-09-09 04:08:42"
  condition:
    hash.sha256(0, filesize) == "7627323dc2af3b1edcb2081f3b91570b61008b539d038a45085342227933026a"
}

rule MalwareBazaar_unknown_005_4dafdbb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dafdbb610afca675acd37d4df766ebf84ab0b903ce270696218a9a9b56f2c13"
    family = "unknown"
    file_name = "EP-342152026_ORDER_QOUTATION_FORMS.js"
    file_type = "js"
    first_seen = "2026-09-09 03:56:36"
  condition:
    hash.sha256(0, filesize) == "4dafdbb610afca675acd37d4df766ebf84ab0b903ce270696218a9a9b56f2c13"
}

rule MalwareBazaar_unknown_006_35d2e3cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d2e3cc6fe69e460a6ec4ea1a406582581bcd17be4807cafe49df8e779e9d99"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-09 03:39:26"
  condition:
    hash.sha256(0, filesize) == "35d2e3cc6fe69e460a6ec4ea1a406582581bcd17be4807cafe49df8e779e9d99"
}

rule MalwareBazaar_unknown_007_50079751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50079751c8f42b0730494ff5482b4684eb62b560be7b1dc4b9c6f27e069a4e95"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-09 03:37:54"
  condition:
    hash.sha256(0, filesize) == "50079751c8f42b0730494ff5482b4684eb62b560be7b1dc4b9c6f27e069a4e95"
}

rule MalwareBazaar_Mirai_008_481ab340
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57"
    family = "Mirai"
    file_name = "481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57.elf"
    file_type = "elf"
    first_seen = "2026-09-09 03:33:45"
  condition:
    hash.sha256(0, filesize) == "481ab3406ddfd6b9cf4c9346b4cb815776fd0d89719344247d0d22c8a20e9e57"
}

rule MalwareBazaar_unknown_009_76361341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76361341b7f86862fae2235d1f67de4c0d3f9ec2ba108328d40b18f7800bc591"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-09 03:27:28"
  condition:
    hash.sha256(0, filesize) == "76361341b7f86862fae2235d1f67de4c0d3f9ec2ba108328d40b18f7800bc591"
}

rule MalwareBazaar_Mirai_010_410fe169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62"
    family = "Mirai"
    file_name = "410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62.elf"
    file_type = "elf"
    first_seen = "2026-09-09 03:23:44"
  condition:
    hash.sha256(0, filesize) == "410fe1699749582a576c43d760128856be27a6cf04a80c0e3ad880ab41aa7c62"
}

rule MalwareBazaar_unknown_011_a5af2c9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5af2c9eead719aae42ef1fd7a8e78b3a1caebd7f053e3bb34cd74a1e5c470ef"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-09 03:20:00"
  condition:
    hash.sha256(0, filesize) == "a5af2c9eead719aae42ef1fd7a8e78b3a1caebd7f053e3bb34cd74a1e5c470ef"
}

rule MalwareBazaar_Mirai_012_dbf8a577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf8a577d037022a5c8834874be21590b399b0dc5e5103241b3d34d723d05186"
    family = "Mirai"
    file_name = "telnetd"
    file_type = "elf"
    first_seen = "2026-09-09 03:19:59"
  condition:
    hash.sha256(0, filesize) == "dbf8a577d037022a5c8834874be21590b399b0dc5e5103241b3d34d723d05186"
}

rule MalwareBazaar_unknown_013_a64f579a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a64f579aaddbfe0f05cf6fdbd528ed98e35ef54d2c9869b35fdd800ef559420b"
    family = "unknown"
    file_name = "youtube-music-free.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:16:08"
  condition:
    hash.sha256(0, filesize) == "a64f579aaddbfe0f05cf6fdbd528ed98e35ef54d2c9869b35fdd800ef559420b"
}

rule MalwareBazaar_unknown_014_6e846994
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421"
    family = "unknown"
    file_name = "6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421.bin"
    file_type = "unknown"
    first_seen = "2026-09-09 03:08:43"
  condition:
    hash.sha256(0, filesize) == "6e846994c31e4877bc946e244136dedb5aa89490b918d1157825e2f818458421"
}

rule MalwareBazaar_ValleyRAT_015_d13752d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d13752d409ddb0e6f87bd72259a343f7a70bd13c30b03943019123a96e4a2070"
    family = "ValleyRAT"
    file_name = "win-Bundle x643014.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:03:20"
  condition:
    hash.sha256(0, filesize) == "d13752d409ddb0e6f87bd72259a343f7a70bd13c30b03943019123a96e4a2070"
}

rule MalwareBazaar_unknown_016_66c9668d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66c9668d460f0d3f71fb0ed42b895d53f90f4415ea9493e1dd2695cb505be9a6"
    family = "unknown"
    file_name = "instell_s2.0.08.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:02:05"
  condition:
    hash.sha256(0, filesize) == "66c9668d460f0d3f71fb0ed42b895d53f90f4415ea9493e1dd2695cb505be9a6"
}

rule MalwareBazaar_unknown_017_db9ce8f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db9ce8f0eed015147b99abe421137da2be91f6496edf937b934c2b4123f0fd4f"
    family = "unknown"
    file_name = "instell_s2.0.07.exe"
    file_type = "exe"
    first_seen = "2026-09-09 03:00:49"
  condition:
    hash.sha256(0, filesize) == "db9ce8f0eed015147b99abe421137da2be91f6496edf937b934c2b4123f0fd4f"
}

rule MalwareBazaar_unknown_018_036fff70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "036fff70e9d3305ecb0234e79d3ae373aa348ba0cf30d5526bcb13d2f51da0f7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-09 02:45:59"
  condition:
    hash.sha256(0, filesize) == "036fff70e9d3305ecb0234e79d3ae373aa348ba0cf30d5526bcb13d2f51da0f7"
}

rule MalwareBazaar_NanoCore_019_2471a6c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2471a6c8da3933f1d8ba41a136fa0ca185801dfd26f73d2f8791449007153444"
    family = "NanoCore"
    file_name = "5CDD5FA5921EA6D54EBDE06166D1AD9A.exe"
    file_type = "exe"
    first_seen = "2026-09-09 02:45:06"
  condition:
    hash.sha256(0, filesize) == "2471a6c8da3933f1d8ba41a136fa0ca185801dfd26f73d2f8791449007153444"
}

rule MalwareBazaar_Mirai_020_35664b1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35664b1b0720aaf383086d2de50e91dbd7fa83f89b8b0dda7d5c1c03ffccc842"
    family = "Mirai"
    file_name = "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
    file_type = "elf"
    first_seen = "2026-09-09 02:40:30"
  condition:
    hash.sha256(0, filesize) == "35664b1b0720aaf383086d2de50e91dbd7fa83f89b8b0dda7d5c1c03ffccc842"
}

rule MalwareBazaar_Mirai_021_b18df0c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b18df0c8e3b445e4f6581b354f0de6fc47b060834ea4867d32524f2e4032eefc"
    family = "Mirai"
    file_name = "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
    file_type = "elf"
    first_seen = "2026-09-09 02:40:28"
  condition:
    hash.sha256(0, filesize) == "b18df0c8e3b445e4f6581b354f0de6fc47b060834ea4867d32524f2e4032eefc"
}

rule MalwareBazaar_unknown_022_db2dfc1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25"
    family = "unknown"
    file_name = "db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25"
    file_type = "unknown"
    first_seen = "2026-09-09 02:40:01"
  condition:
    hash.sha256(0, filesize) == "db2dfc1e627fb90bd986951fff590c1f4d0df26fca0ad2af94ccfdec2ab6aa25"
}

rule MalwareBazaar_Mirai_023_ecee64f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
    family = "Mirai"
    file_name = "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
    file_type = "elf"
    first_seen = "2026-09-09 02:39:59"
  condition:
    hash.sha256(0, filesize) == "ecee64f2446c402df5024227ab3217e82ce4f40fd3f509a306ce731de3fa71a4"
}

rule MalwareBazaar_Mirai_024_bdaf3c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
    family = "Mirai"
    file_name = "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
    file_type = "elf"
    first_seen = "2026-09-09 02:39:56"
  condition:
    hash.sha256(0, filesize) == "bdaf3c99c0dc9f4a9b75b30f228dd64f168de46da83546f8c3b7d93bc7298bae"
}

rule MalwareBazaar_Mirai_025_a0983541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a"
    family = "Mirai"
    file_name = "a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a"
    file_type = "sh"
    first_seen = "2026-09-09 02:39:54"
  condition:
    hash.sha256(0, filesize) == "a0983541675c369ca18843d757644db9f33de26ca9c5373c1bf61a67ca4c908a"
}

rule MalwareBazaar_Mirai_026_b7ed37d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7ed37d1f689a8302fecfb64ef4bc8828603d093926996965faca45e1ae869a8"
    family = "Mirai"
    file_name = "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
    file_type = "elf"
    first_seen = "2026-09-09 02:38:16"
  condition:
    hash.sha256(0, filesize) == "b7ed37d1f689a8302fecfb64ef4bc8828603d093926996965faca45e1ae869a8"
}

rule MalwareBazaar_Mirai_027_a8655c03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634"
    family = "Mirai"
    file_name = "a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634"
    file_type = "elf"
    first_seen = "2026-09-09 02:37:47"
  condition:
    hash.sha256(0, filesize) == "a8655c0314ffb2321cf53e6965271ae02a3a67af8cf9c89b163090e7e5b68634"
}

rule MalwareBazaar_Mirai_028_10022690
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
    family = "Mirai"
    file_name = "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
    file_type = "elf"
    first_seen = "2026-09-09 02:37:35"
  condition:
    hash.sha256(0, filesize) == "1002269048f762683b0f553c5634460fa709390598b3cf2b7021bd6c453c08d6"
}

rule MalwareBazaar_unknown_029_9e8d5a90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e8d5a90140383c459626e04b5e44288f90b6952da0cd10bb15d621f7093d35c"
    family = "unknown"
    file_name = "Havnelbene.vbs"
    file_type = "vbs"
    first_seen = "2026-09-09 02:32:31"
  condition:
    hash.sha256(0, filesize) == "9e8d5a90140383c459626e04b5e44288f90b6952da0cd10bb15d621f7093d35c"
}

rule MalwareBazaar_VShell_030_6be8c092
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91"
    family = "VShell"
    file_name = "6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91.exe"
    file_type = "exe"
    first_seen = "2026-09-09 02:14:11"
  condition:
    hash.sha256(0, filesize) == "6be8c092507dc1e7105e56f5c5aaae527be511884105b1b3895ba6ce1d869d91"
}

rule MalwareBazaar_unknown_031_8c6b26ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b"
    family = "unknown"
    file_name = "8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b.bin"
    file_type = "exe"
    first_seen = "2026-09-09 01:53:46"
  condition:
    hash.sha256(0, filesize) == "8c6b26ab06165ec54247dcd7b4c2b30b23c9ffcf7c08f17947b86e3324d4e01b"
}

rule MalwareBazaar_unknown_032_8e832126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8"
    family = "unknown"
    file_name = "8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8.bin"
    file_type = "exe"
    first_seen = "2026-09-09 01:53:43"
  condition:
    hash.sha256(0, filesize) == "8e8321260017a015165b1c3f6cbc2ed83324f2da95a8d39d71ff1877c00b4fa8"
}

rule MalwareBazaar_VShell_033_e12dbf04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6"
    family = "VShell"
    file_name = "e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6.exe"
    file_type = "exe"
    first_seen = "2026-09-09 01:08:41"
  condition:
    hash.sha256(0, filesize) == "e12dbf049019f00e5ad30e55e04314a080491617cca6b099d81334ae43458dd6"
}

rule MalwareBazaar_Mirai_034_e3e5faa2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22"
    family = "Mirai"
    file_name = "e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22.elf"
    file_type = "elf"
    first_seen = "2026-09-09 00:58:42"
  condition:
    hash.sha256(0, filesize) == "e3e5faa2660cd86e4608017e59a1808a5d2491b56b1b87757ba539e19c457c22"
}

rule MalwareBazaar_Mirai_035_b9a8f948
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077"
    family = "Mirai"
    file_name = "b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077.elf"
    file_type = "elf"
    first_seen = "2026-09-09 00:34:16"
  condition:
    hash.sha256(0, filesize) == "b9a8f948feb4057aeec015eee181ceb5b5e7286f76d1215df249ce726b5c9077"
}

rule MalwareBazaar_unknown_036_e7be5fda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357"
    family = "unknown"
    file_name = "e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357.bin"
    file_type = "exe"
    first_seen = "2026-09-09 00:28:56"
  condition:
    hash.sha256(0, filesize) == "e7be5fda5fc08571870d19a5006aba7b23c5ed2271d3b0a5449b7c6d078c9357"
}

rule MalwareBazaar_VShell_037_f341190f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3"
    family = "VShell"
    file_name = "f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3.exe"
    file_type = "exe"
    first_seen = "2026-09-09 00:08:51"
  condition:
    hash.sha256(0, filesize) == "f341190f94840430742555f0ef402c162ab7fe5cd736923cb579a1ae33be47e3"
}

rule MalwareBazaar_unknown_038_c3e430b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3e430b1716764ca82d8a25db5d19e2239018bf426e7c6d4b5e769ddce469ad9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 23:40:50"
  condition:
    hash.sha256(0, filesize) == "c3e430b1716764ca82d8a25db5d19e2239018bf426e7c6d4b5e769ddce469ad9"
}

rule MalwareBazaar_unknown_039_82a4e2fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a4e2fe38d95392e19f9b8618df2ce0811d40a1aabc3a226b4d4c69a0bd5e7c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 23:37:41"
  condition:
    hash.sha256(0, filesize) == "82a4e2fe38d95392e19f9b8618df2ce0811d40a1aabc3a226b4d4c69a0bd5e7c"
}

rule MalwareBazaar_Mirai_040_9dea0a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dea0a840f4925b3a5d7b25d9c6281838ec3247b6938c3883d7f3b98545e71b1"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-09-08 23:13:34"
  condition:
    hash.sha256(0, filesize) == "9dea0a840f4925b3a5d7b25d9c6281838ec3247b6938c3883d7f3b98545e71b1"
}

rule MalwareBazaar_Mirai_041_c630cb38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c630cb386ed061f395b2527513b40f45d5c857637856cdacef856a6b061ff277"
    family = "Mirai"
    file_name = "boatnet.arc"
    file_type = "elf"
    first_seen = "2026-09-08 23:13:32"
  condition:
    hash.sha256(0, filesize) == "c630cb386ed061f395b2527513b40f45d5c857637856cdacef856a6b061ff277"
}

rule MalwareBazaar_unknown_042_67c4c5ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67c4c5ac61391f6faa60aa021e66b7fed80aab9f9d3f2cae1f6b008b42b126cf"
    family = "unknown"
    file_name = "trouserstreak.net__trouser-streak-1.6.1-1.21.4.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:24"
  condition:
    hash.sha256(0, filesize) == "67c4c5ac61391f6faa60aa021e66b7fed80aab9f9d3f2cae1f6b008b42b126cf"
}

rule MalwareBazaar_unknown_043_9053f8d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9053f8d71dcc63275a24bbaa1be86d963ce3165e58343f0b29649855b7162f8c"
    family = "unknown"
    file_name = "trouserstreak.net__trouser-streak-1.6.1-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:17"
  condition:
    hash.sha256(0, filesize) == "9053f8d71dcc63275a24bbaa1be86d963ce3165e58343f0b29649855b7162f8c"
}

rule MalwareBazaar_unknown_044_f72cecb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f72cecb79c59fc50cde41400d9ca422d303cd444769e7ec9423889136a7a93aa"
    family = "unknown"
    file_name = "meteorrejects.net__meteor-rejects-addon-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:11"
  condition:
    hash.sha256(0, filesize) == "f72cecb79c59fc50cde41400d9ca422d303cd444769e7ec9423889136a7a93aa"
}

rule MalwareBazaar_unknown_045_35222d50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35222d50b11bc02bfb6bcb3127b5a55179bbd1112042466d26799e7c08d86287"
    family = "unknown"
    file_name = "novowareclient.com__inline-payload.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:01:03"
  condition:
    hash.sha256(0, filesize) == "35222d50b11bc02bfb6bcb3127b5a55179bbd1112042466d26799e7c08d86287"
}

rule MalwareBazaar_unknown_046_81626e1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81626e1e1cd90448bd07f46ae54efa2e3a0682986a28a11a77d8b436db880d92"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc26_1_2.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:54"
  condition:
    hash.sha256(0, filesize) == "81626e1e1cd90448bd07f46ae54efa2e3a0682986a28a11a77d8b436db880d92"
}

rule MalwareBazaar_unknown_047_29ad5672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ad567237511d625f13a68132875460399aac101ec9ae6a3d43e3bfbb6a4aa0"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_11.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:48"
  condition:
    hash.sha256(0, filesize) == "29ad567237511d625f13a68132875460399aac101ec9ae6a3d43e3bfbb6a4aa0"
}

rule MalwareBazaar_unknown_048_3dcc6c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dcc6c98de31c5100a71f6ccc21597ca80ec40ddb11a21f3b924cde42816c622"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_10.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:42"
  condition:
    hash.sha256(0, filesize) == "3dcc6c98de31c5100a71f6ccc21597ca80ec40ddb11a21f3b924cde42816c622"
}

rule MalwareBazaar_unknown_049_5d5c3836
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5c3836211ea4d757334687b12105d4e9f842ad9f6ee7ef655185e98c02e12a"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_4.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:35"
  condition:
    hash.sha256(0, filesize) == "5d5c3836211ea4d757334687b12105d4e9f842ad9f6ee7ef655185e98c02e12a"
}

rule MalwareBazaar_unknown_050_a0d5fc7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0d5fc7c7125ea1b4803a4059db8a3b88282e0fb13df14c02d334a368dbe2cc8"
    family = "unknown"
    file_name = "meteor-gui-addon.com__Meteor-GUI-addon-2_2_0_mc1_21_1.jar"
    file_type = "jar"
    first_seen = "2026-09-08 23:00:29"
  condition:
    hash.sha256(0, filesize) == "a0d5fc7c7125ea1b4803a4059db8a3b88282e0fb13df14c02d334a368dbe2cc8"
}

rule MalwareBazaar_unknown_051_62c07b17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c07b174de63a5035ce50fb11a9c1636e26fde96a0f368df1e71e7789f73230"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-08 22:50:32"
  condition:
    hash.sha256(0, filesize) == "62c07b174de63a5035ce50fb11a9c1636e26fde96a0f368df1e71e7789f73230"
}

rule MalwareBazaar_Mirai_052_c19d15ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c19d15ff0145110b8f9357c14ae5c61f92fc7eb20e5b2a1953c70a6673ac7530"
    family = "Mirai"
    file_name = "titan.mipsel"
    file_type = "elf"
    first_seen = "2026-09-08 22:48:56"
  condition:
    hash.sha256(0, filesize) == "c19d15ff0145110b8f9357c14ae5c61f92fc7eb20e5b2a1953c70a6673ac7530"
}

rule MalwareBazaar_unknown_053_86953022
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86953022ccd295b02be2202be2e2d9d8d87ef719d1aa368ca16c30a33fcdbd63"
    family = "unknown"
    file_name = "KiddonsModMenu.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:39:47"
  condition:
    hash.sha256(0, filesize) == "86953022ccd295b02be2202be2e2d9d8d87ef719d1aa368ca16c30a33fcdbd63"
}

rule MalwareBazaar_unknown_054_71866496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71866496dfb4b741274cdba933e8f9fe0209542e5198d8e9b240d967070bc1c4"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-08 22:38:34"
  condition:
    hash.sha256(0, filesize) == "71866496dfb4b741274cdba933e8f9fe0209542e5198d8e9b240d967070bc1c4"
}

rule MalwareBazaar_unknown_055_007e5fba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "007e5fba613f08c75b4073409e63b03622623a4d12b25ab8bca74bb68db77f5b"
    family = "unknown"
    file_name = "executorfree.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:37:45"
  condition:
    hash.sha256(0, filesize) == "007e5fba613f08c75b4073409e63b03622623a4d12b25ab8bca74bb68db77f5b"
}

rule MalwareBazaar_unknown_056_b350924a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b350924ace363c1d4980aa1d5022d48f4591df1c701d32c5147428273dfa56a8"
    family = "unknown"
    file_name = "larpexodus.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:36:29"
  condition:
    hash.sha256(0, filesize) == "b350924ace363c1d4980aa1d5022d48f4591df1c701d32c5147428273dfa56a8"
}

rule MalwareBazaar_Mirai_057_97921a2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97921a2cfacb0b73fc7d14e29b751862b4bd0f02972d2af64cfdf8e0e802ab6f"
    family = "Mirai"
    file_name = "titan.x64-test"
    file_type = "elf"
    first_seen = "2026-09-08 22:30:35"
  condition:
    hash.sha256(0, filesize) == "97921a2cfacb0b73fc7d14e29b751862b4bd0f02972d2af64cfdf8e0e802ab6f"
}

rule MalwareBazaar_SilentNet_058_96d443a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96d443a8f6fbb22ef7a1462d57b39591cbd465ba391a8c6e2c41fa3df7f92f0c"
    family = "SilentNet"
    file_name = "fortnite loader.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:30:28"
  condition:
    hash.sha256(0, filesize) == "96d443a8f6fbb22ef7a1462d57b39591cbd465ba391a8c6e2c41fa3df7f92f0c"
}

rule MalwareBazaar_unknown_059_1a15976c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419"
    family = "unknown"
    file_name = "1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419"
    file_type = "unknown"
    first_seen = "2026-09-08 22:30:24"
  condition:
    hash.sha256(0, filesize) == "1a15976ce2e12f816a35c56ae3df7655721311111142fc1fbdb18ce42515a419"
}

rule MalwareBazaar_Mirai_060_2a64b441
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a64b441a105af29fd5fcd48bd7215f1044b045f85ba47d5b58cb888e1b20b74"
    family = "Mirai"
    file_name = "titan.arm6"
    file_type = "elf"
    first_seen = "2026-09-08 22:24:35"
  condition:
    hash.sha256(0, filesize) == "2a64b441a105af29fd5fcd48bd7215f1044b045f85ba47d5b58cb888e1b20b74"
}

rule MalwareBazaar_unknown_061_3e783422
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e7834229ec2359bd079dc08736aefe31c67a9a2a15e90016e371e1416c39d19"
    family = "unknown"
    file_name = "Simple Cheats Client.zip"
    file_type = "zip"
    first_seen = "2026-09-08 22:22:43"
  condition:
    hash.sha256(0, filesize) == "3e7834229ec2359bd079dc08736aefe31c67a9a2a15e90016e371e1416c39d19"
}

rule MalwareBazaar_unknown_062_a19fce7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a19fce7dfd85822b3dcc3fad77b0d91ac2740fc5a739f5741a1d3294ca2135bb"
    family = "unknown"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:20:22"
  condition:
    hash.sha256(0, filesize) == "a19fce7dfd85822b3dcc3fad77b0d91ac2740fc5a739f5741a1d3294ca2135bb"
}

rule MalwareBazaar_unknown_063_b20b4000
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20b400002fd59a805b29118861b48480a0eb20001fc23561df311a93cef57f2"
    family = "unknown"
    file_name = "decrypted_payload.exe"
    file_type = "exe"
    first_seen = "2026-09-08 22:16:54"
  condition:
    hash.sha256(0, filesize) == "b20b400002fd59a805b29118861b48480a0eb20001fc23561df311a93cef57f2"
}

rule MalwareBazaar_unknown_064_e2505b68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2505b685cc4ab141172a1d2d70beb2e2683e4c96fb3f29e9a9c7476a0a1360d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-08 22:14:33"
  condition:
    hash.sha256(0, filesize) == "e2505b685cc4ab141172a1d2d70beb2e2683e4c96fb3f29e9a9c7476a0a1360d"
}

rule MalwareBazaar_unknown_065_e3da33cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3da33cd23e733ec215120582627110a37c6b97bfdefd36534240fd29b807016"
    family = "unknown"
    file_name = "Taiwanske.vbs"
    file_type = "vbs"
    first_seen = "2026-09-08 22:12:28"
  condition:
    hash.sha256(0, filesize) == "e3da33cd23e733ec215120582627110a37c6b97bfdefd36534240fd29b807016"
}

rule MalwareBazaar_unknown_066_f3194a74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3194a746e0b91fa649eed5ccb0d43e1eb4cb87d41249fb5f38bd2740b9bbca0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 22:04:47"
  condition:
    hash.sha256(0, filesize) == "f3194a746e0b91fa649eed5ccb0d43e1eb4cb87d41249fb5f38bd2740b9bbca0"
}

rule MalwareBazaar_Mirai_067_4d79178f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d79178fa6d7f0627caef122e3c29a0a95a0802ba5a050041660f4d6e11adbfd"
    family = "Mirai"
    file_name = "titan.m68k"
    file_type = "elf"
    first_seen = "2026-09-08 22:03:31"
  condition:
    hash.sha256(0, filesize) == "4d79178fa6d7f0627caef122e3c29a0a95a0802ba5a050041660f4d6e11adbfd"
}

rule MalwareBazaar_Mirai_068_0e4ed32d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e4ed32d4ca30f45369fa17f7a8b90c0fa9f2f9ece78048c6922ccaf1853bd8d"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-08 21:56:33"
  condition:
    hash.sha256(0, filesize) == "0e4ed32d4ca30f45369fa17f7a8b90c0fa9f2f9ece78048c6922ccaf1853bd8d"
}

rule MalwareBazaar_unknown_069_94cacfa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94cacfa7fcb76873c69243f5e651aa8ff7b21e4821065275e8cd6d419d49462d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-08 21:54:57"
  condition:
    hash.sha256(0, filesize) == "94cacfa7fcb76873c69243f5e651aa8ff7b21e4821065275e8cd6d419d49462d"
}

rule MalwareBazaar_unknown_070_ec0e9d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97"
    family = "unknown"
    file_name = "ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97.bin"
    file_type = "unknown"
    first_seen = "2026-09-08 21:53:42"
  condition:
    hash.sha256(0, filesize) == "ec0e9d8225568992658c7c85e87090d7c07c0c658fe28e2acfe8ef647fd77c97"
}

rule MalwareBazaar_Mirai_071_8865cec6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8865cec6bfc4cacc0fa38975628a6c1b32f71aa6a92446ee55414e8d2f85a2e5"
    family = "Mirai"
    file_name = "titan.x32"
    file_type = "elf"
    first_seen = "2026-09-08 21:51:32"
  condition:
    hash.sha256(0, filesize) == "8865cec6bfc4cacc0fa38975628a6c1b32f71aa6a92446ee55414e8d2f85a2e5"
}

rule MalwareBazaar_Mirai_072_f5278090
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f527809022eef86d0921595f93229b802ea12fa3a140456c585f877da57fa698"
    family = "Mirai"
    file_name = "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:44:18"
  condition:
    hash.sha256(0, filesize) == "f527809022eef86d0921595f93229b802ea12fa3a140456c585f877da57fa698"
}

rule MalwareBazaar_Mirai_073_20627e7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c"
    family = "Mirai"
    file_name = "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:43:44"
  condition:
    hash.sha256(0, filesize) == "20627e7bbf0bd28d5c9b150498e926332d9eca4b39804a6e53907d4a6597a27c"
}

rule MalwareBazaar_unknown_074_f601cde9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7"
    family = "unknown"
    file_name = "f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7.bin"
    file_type = "exe"
    first_seen = "2026-09-08 21:43:34"
  condition:
    hash.sha256(0, filesize) == "f601cde9845b729dcbbcd0b8b972baff995c8ed2b81f5469ffd1693051b44fc7"
}

rule MalwareBazaar_unknown_075_f1142e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3"
    family = "unknown"
    file_name = "f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3.bin"
    file_type = "exe"
    first_seen = "2026-09-08 21:43:33"
  condition:
    hash.sha256(0, filesize) == "f1142e07e25d8178dfddd10b442f12a14b920c133f1a64b05a6ad58dd98068a3"
}

rule MalwareBazaar_Mirai_076_65dd73ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4"
    family = "Mirai"
    file_name = "65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:39:24"
  condition:
    hash.sha256(0, filesize) == "65dd73ff6820fdc0aa1b7d449a1979592bc6f46a9d7a91bd6800c31268503fd4"
}

rule MalwareBazaar_Mirai_077_06710dd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06710dd73fee4a517b98dac1823e091bb3defdef400d7a20c65ea78eb85c0f52"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-08 21:34:32"
  condition:
    hash.sha256(0, filesize) == "06710dd73fee4a517b98dac1823e091bb3defdef400d7a20c65ea78eb85c0f52"
}

rule MalwareBazaar_Mirai_078_b882d762
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b882d7626ff89aa52514fdb06a9333db386e98b31937d0184d65c8ba70474eed"
    family = "Mirai"
    file_name = "titan.ppc440"
    file_type = "elf"
    first_seen = "2026-09-08 21:31:00"
  condition:
    hash.sha256(0, filesize) == "b882d7626ff89aa52514fdb06a9333db386e98b31937d0184d65c8ba70474eed"
}

rule MalwareBazaar_unknown_079_7fb8a786
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fb8a78604d0f7df0734cde30c48babf079926abcba3c4725b68b43c872c8f0b"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-08 21:30:59"
  condition:
    hash.sha256(0, filesize) == "7fb8a78604d0f7df0734cde30c48babf079926abcba3c4725b68b43c872c8f0b"
}

rule MalwareBazaar_unknown_080_d49b6364
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d49b6364096bad20e30d3c2be46c9aac136626f26f78ba0dc19ced6f897b073e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-08 21:27:32"
  condition:
    hash.sha256(0, filesize) == "d49b6364096bad20e30d3c2be46c9aac136626f26f78ba0dc19ced6f897b073e"
}

rule MalwareBazaar_Mirai_081_25d77582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d775826462960f3e9aac0a58c5317f69809f2a403c09a242bbec88e0792069"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-08 21:27:31"
  condition:
    hash.sha256(0, filesize) == "25d775826462960f3e9aac0a58c5317f69809f2a403c09a242bbec88e0792069"
}

rule MalwareBazaar_Mirai_082_1476885c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1476885ceabb54b25f302d2fa363a87b3b11a4616328fa0844bb9e7a160d5946"
    family = "Mirai"
    file_name = "titan.sh4"
    file_type = "elf"
    first_seen = "2026-09-08 21:25:58"
  condition:
    hash.sha256(0, filesize) == "1476885ceabb54b25f302d2fa363a87b3b11a4616328fa0844bb9e7a160d5946"
}

rule MalwareBazaar_Mirai_083_57a89658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a8965812e8f5bb8f9f0abff20e77333c8072f530adc970ccabbaa9ccf6e1dd"
    family = "Mirai"
    file_name = "titan.arm7"
    file_type = "elf"
    first_seen = "2026-09-08 21:25:57"
  condition:
    hash.sha256(0, filesize) == "57a8965812e8f5bb8f9f0abff20e77333c8072f530adc970ccabbaa9ccf6e1dd"
}

rule MalwareBazaar_Mirai_084_57130207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57130207e60dc0596100e86cc67e288dd092fd3ffaeb230f8a1fd975797b56d0"
    family = "Mirai"
    file_name = "titan.mips"
    file_type = "elf"
    first_seen = "2026-09-08 21:24:29"
  condition:
    hash.sha256(0, filesize) == "57130207e60dc0596100e86cc67e288dd092fd3ffaeb230f8a1fd975797b56d0"
}

rule MalwareBazaar_Mirai_085_c9b0003d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9b0003da146ddc53fc6d4b77e91942b1298d9bd159a2a02dc2fa4ef20c7148f"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-08 21:20:33"
  condition:
    hash.sha256(0, filesize) == "c9b0003da146ddc53fc6d4b77e91942b1298d9bd159a2a02dc2fa4ef20c7148f"
}

rule MalwareBazaar_Mirai_086_c55604b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690"
    family = "Mirai"
    file_name = "c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:20:02"
  condition:
    hash.sha256(0, filesize) == "c55604b959e8c9850dc7124df0a9a1c77e286980de39d6583029949bf4a2d690"
}

rule MalwareBazaar_Mirai_087_56ee7631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56ee76316c9c8d9561cf318fb1d1439d069c7fe9da91214ce976e8c3beb8cd4b"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-08 21:19:54"
  condition:
    hash.sha256(0, filesize) == "56ee76316c9c8d9561cf318fb1d1439d069c7fe9da91214ce976e8c3beb8cd4b"
}

rule MalwareBazaar_Mirai_088_8127b15b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e"
    family = "Mirai"
    file_name = "8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e.elf"
    file_type = "elf"
    first_seen = "2026-09-08 21:19:38"
  condition:
    hash.sha256(0, filesize) == "8127b15b21a3373301672aa6d7b8f3c99014f82b17725303698563a45710dc4e"
}

rule MalwareBazaar_ConnectWise_089_474187eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11"
    family = "ConnectWise"
    file_name = "474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11.exe"
    file_type = "exe"
    first_seen = "2026-09-08 21:18:47"
  condition:
    hash.sha256(0, filesize) == "474187ebbc6b0dce7ea694222581f40e23971023158fb74e8404e04180254e11"
}

rule MalwareBazaar_Mirai_090_78c76597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78c765978a0c2683eddafbbcc6e7896bf7172d63a936c602457034064016f3a5"
    family = "Mirai"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-09-08 21:16:55"
  condition:
    hash.sha256(0, filesize) == "78c765978a0c2683eddafbbcc6e7896bf7172d63a936c602457034064016f3a5"
}

rule MalwareBazaar_Mirai_091_9ccc4db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae"
    family = "Mirai"
    file_name = "titan.arm5"
    file_type = "elf"
    first_seen = "2026-09-08 21:15:29"
  condition:
    hash.sha256(0, filesize) == "9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae"
}

rule MalwareBazaar_ConnectWise_092_b4b9fa7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329"
    family = "ConnectWise"
    file_name = "b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329.msi"
    file_type = "msi"
    first_seen = "2026-09-08 21:08:54"
  condition:
    hash.sha256(0, filesize) == "b4b9fa7c5472840a6d122c5550fbc6aa346c58361d6dc38e1f53894ca3387329"
}

rule MalwareBazaar_unknown_093_a3d1af63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3d1af638d5f16e7e2aa9aea53fe2da960f4068e628ff9c6a5cf9a696a198cb1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-08 21:04:52"
  condition:
    hash.sha256(0, filesize) == "a3d1af638d5f16e7e2aa9aea53fe2da960f4068e628ff9c6a5cf9a696a198cb1"
}

rule MalwareBazaar_unknown_094_97f2d703
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97f2d7035e4a4e3d1d832e091cd229e7bec93525e7e3c22bed7dd43063181674"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-08 21:04:51"
  condition:
    hash.sha256(0, filesize) == "97f2d7035e4a4e3d1d832e091cd229e7bec93525e7e3c22bed7dd43063181674"
}

rule MalwareBazaar_Mirai_095_0d85349b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d85349b8f1c736d103ac566fbf28b895e0565c545bece7633ff19778f40408b"
    family = "Mirai"
    file_name = "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:54:17"
  condition:
    hash.sha256(0, filesize) == "0d85349b8f1c736d103ac566fbf28b895e0565c545bece7633ff19778f40408b"
}

rule MalwareBazaar_Mirai_096_7b93ebd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027"
    family = "Mirai"
    file_name = "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:53:49"
  condition:
    hash.sha256(0, filesize) == "7b93ebd36c707e336610fd34e41c17d276b85840b773b4063141a5acd3200027"
}

rule MalwareBazaar_unknown_097_073bc6f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "073bc6f44e0f2c23183f87f73e413e74e21d185f2974183d9b5ca1cb8bd3e1d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-08 20:48:45"
  condition:
    hash.sha256(0, filesize) == "073bc6f44e0f2c23183f87f73e413e74e21d185f2974183d9b5ca1cb8bd3e1d7"
}

rule MalwareBazaar_Mirai_098_4bccec3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bccec3aec8dbdda25d35e893921a5f5fcf02ed2145e0c34841a529654621919"
    family = "Mirai"
    file_name = "titan.arm7"
    file_type = "elf"
    first_seen = "2026-09-08 20:32:55"
  condition:
    hash.sha256(0, filesize) == "4bccec3aec8dbdda25d35e893921a5f5fcf02ed2145e0c34841a529654621919"
}

rule MalwareBazaar_Mirai_099_2a6a7d52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a6a7d52100618b5a38a8ec50c425d8137cfe1f33d86d526f474ed942f871e71"
    family = "Mirai"
    file_name = "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:29:25"
  condition:
    hash.sha256(0, filesize) == "2a6a7d52100618b5a38a8ec50c425d8137cfe1f33d86d526f474ed942f871e71"
}

rule MalwareBazaar_Mirai_100_8876d082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478"
    family = "Mirai"
    file_name = "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478.elf"
    file_type = "elf"
    first_seen = "2026-09-08 20:29:14"
  condition:
    hash.sha256(0, filesize) == "8876d082a455b569c9f50f98f4d25097f94b769e2e5701beafa182ea19911478"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

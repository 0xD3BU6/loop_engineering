# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-05

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 671 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 671 |
| Unique family labels | 14 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 46 |
| unknown | 35 |
| Gafgyt | 5 |
| Gh0stRAT | 3 |
| VShell | 2 |
| RemcosRAT | 1 |
| Formbook | 1 |
| WannaCry | 1 |
| CoinMiner | 1 |
| PythonStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 56 |
| exe | 24 |
| hta | 5 |
| sh | 3 |
| js | 2 |
| dll | 2 |
| macho | 2 |
| r00 | 1 |
| ps1 | 1 |
| apk | 1 |

## Per-Sample Analysis

### Sample 1: `f88971f2b24f63bc`

| Field | Value |
|---|---|
| SHA-256 | `f88971f2b24f63bcb40e9a01ac8bc79850c9ea0410eb2f11ad5400cea34553da` |
| Family label | `RemcosRAT` |
| File name | `IMG-Bill - Ref#843993400 New GROUP BOOKING - SOA.r00` |
| File type | `r00` |
| First seen | `2026-10-05 05:30:55` |
| Reporter | `ppt_lol` |
| Tags | `r00, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c71b1a2da29ded2e9fae8f7f682c7b1` |
| SHA-1 | `809d4f1cf5789089919b8fbe15d6f6e8f0a80683` |
| SHA-256 | `f88971f2b24f63bcb40e9a01ac8bc79850c9ea0410eb2f11ad5400cea34553da` |
| SHA3-384 | `b874c8f1326ac7cdb2f7dbeeb1f6f5a8aa6ad3a30fb2c451bb3232b30c781f4f739f41c72a8e34c80f7529f697833424` |
| TLSH | `T1418533AD2BE74D951C706C2F8E4B9B7C48372CDFC5C8E953E199A8AA9E1720D52030DD` |
| SSDEEP | `24576:digOv8FR1ONNC8JiMec7AdTAMqlb6EEoW5ApG/Ii4Lm0VwCk6bKyn8WgdDdzdMFc:JOvcOCy7Ad5qlWrT49iJCk6b6dDdzdMe` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `r00`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_001_f88971f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f88971f2b24f63bcb40e9a01ac8bc79850c9ea0410eb2f11ad5400cea34553da"
    family = "RemcosRAT"
    file_name = "IMG-Bill - Ref#843993400 New GROUP BOOKING - SOA.r00"
    file_type = "r00"
    first_seen = "2026-10-05 05:30:55"
  condition:
    hash.sha256(0, filesize) == "f88971f2b24f63bcb40e9a01ac8bc79850c9ea0410eb2f11ad5400cea34553da"
}
```

### Sample 2: `cf024ccc3be3c078`

| Field | Value |
|---|---|
| SHA-256 | `cf024ccc3be3c078e5d34d4e5543068b8d3faac8f3ea3e3e7db614193397d886` |
| Family label | `unknown` |
| File name | `tux-typing_QRi-mp3.exe` |
| File type | `exe` |
| First seen | `2026-10-05 05:29:08` |
| Reporter | `seiffawal` |
| Tags | `adware, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59f3b09d40835ec805a7fcab8188bbde` |
| SHA-1 | `1433de63c5e00d2077b30380f5a3195ad3f8521f` |
| SHA-256 | `cf024ccc3be3c078e5d34d4e5543068b8d3faac8f3ea3e3e7db614193397d886` |
| SHA3-384 | `25f9259d42154843130169c0093680e2eeab56d8854d86a8243bff7d9a5ac4f4d6dba23007f971659b96384c0735d419` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T10B56123FE28BA13EE06A1A3939B29210593BBA6165174C4696FCF44CCF654B01D3E7C7` |
| SSDEEP | `98304:65O2WR3uMooQbPrURINHAa2JiCdJ9YKzoFOqQtAwKLoa2rexaycQwK1G5J/DujUG:2lwKoyURXNYKzogqQtAwKLD2KxaQF1uy` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_cf024ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf024ccc3be3c078e5d34d4e5543068b8d3faac8f3ea3e3e7db614193397d886"
    family = "unknown"
    file_name = "tux-typing_QRi-mp3.exe"
    file_type = "exe"
    first_seen = "2026-10-05 05:29:08"
  condition:
    hash.sha256(0, filesize) == "cf024ccc3be3c078e5d34d4e5543068b8d3faac8f3ea3e3e7db614193397d886"
}
```

### Sample 3: `885bf8bae75d79f0`

| Field | Value |
|---|---|
| SHA-256 | `885bf8bae75d79f0911beb71b29caa16e8fdfdb0ab7115164ce1dc3c1951b6c6` |
| Family label | `unknown` |
| File name | `885bf8bae75d79f0.bin` |
| File type | `elf` |
| First seen | `2026-10-05 05:25:56` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9ff4e78e0b8a4e0adb95500619db7eb` |
| SHA-1 | `b8818ac515d057c0f0bbb3cfd1d36ea2d0149b78` |
| SHA-256 | `885bf8bae75d79f0911beb71b29caa16e8fdfdb0ab7115164ce1dc3c1951b6c6` |
| SHA3-384 | `605bf2f195a29a0f7b04cd2d0847359d34086ea8d9a783b22e1371d734d293ce4b8e387b690c612b3a79e34d116980e3` |
| TLSH | `T108E2A64F6E328FDDF669C7344AF34A30A759238326E1C686D36CD1501E6024E989FBE5` |
| TELFHASH | `t184e0e51c1ab413a436348859485def57d1e030df77263c178b1314f977fc8425d29d04` |
| SSDEEP | `768:TFPuV73QkxfPgmj2/S6QvsKkkeDrHyf3sqD:TVuVN8SDviU3sQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_885bf8ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "885bf8bae75d79f0911beb71b29caa16e8fdfdb0ab7115164ce1dc3c1951b6c6"
    family = "unknown"
    file_name = "885bf8bae75d79f0.bin"
    file_type = "elf"
    first_seen = "2026-10-05 05:25:56"
  condition:
    hash.sha256(0, filesize) == "885bf8bae75d79f0911beb71b29caa16e8fdfdb0ab7115164ce1dc3c1951b6c6"
}
```

### Sample 4: `a0aaff2946ba2bf5`

| Field | Value |
|---|---|
| SHA-256 | `a0aaff2946ba2bf57f5e94c081bf289a8ddb7f2edee21ba0be9796c769946f76` |
| Family label | `Formbook` |
| File name | `FLF7997_SHIPMENT_DETAILS.com` |
| File type | `exe` |
| First seen | `2026-10-05 05:23:24` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ab8080fb2028181d7241e824d569cf2` |
| SHA-1 | `ea3fd1dbcc5800814033fae89859a62973bfc6cc` |
| SHA-256 | `a0aaff2946ba2bf57f5e94c081bf289a8ddb7f2edee21ba0be9796c769946f76` |
| SHA3-384 | `45f3e01b917018a9b99da10f897af0bf2947e3fcfd1f8a2b09b85139dde4806cb078213f4f790176525ca7210af6f368` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16715F114335ECA12C4A957F41D30E6B807B4AD6DA421D3078EEAFCEF793AB5069142E7` |
| SSDEEP | `24576:aR8EIDoc1Gz2baGiBn5of/UFmueqhXMaA/ngyJIMLl+ZB:MDID/C2sCf2mueevA/gyJIUU` |
| ICON-DHASH | `b270ccbaf0e4d4d4` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_004_a0aaff29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0aaff2946ba2bf57f5e94c081bf289a8ddb7f2edee21ba0be9796c769946f76"
    family = "Formbook"
    file_name = "FLF7997_SHIPMENT_DETAILS.com"
    file_type = "exe"
    first_seen = "2026-10-05 05:23:24"
  condition:
    hash.sha256(0, filesize) == "a0aaff2946ba2bf57f5e94c081bf289a8ddb7f2edee21ba0be9796c769946f76"
}
```

### Sample 5: `dad6d4446092e2c9`

| Field | Value |
|---|---|
| SHA-256 | `dad6d4446092e2c99d3ad7ffbf39adb1757c282f4ac7bc2407132882311e3c1e` |
| Family label | `unknown` |
| File name | `temp.hta` |
| File type | `hta` |
| First seen | `2026-10-05 05:18:45` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa4728f9454b69056d5d110d59666a56` |
| SHA-1 | `ce049d78c4fbb3823563cadcb0fbcc59974454b8` |
| SHA-256 | `dad6d4446092e2c99d3ad7ffbf39adb1757c282f4ac7bc2407132882311e3c1e` |
| SHA3-384 | `abcea46b04b6ef3a7cd44bc2f5d771c95b71758231236fca978a98a1f75a9ac5fd81438e07697542c2604776a2fe8183` |
| TLSH | `T18842185CAED1A2B0FA1707DEB3AF24690228A0C7240DC484F94CDDE87F46BDD4A57B56` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzNbqFtCwS1RUM:sXX+/DV7k/3IFtaRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_dad6d444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dad6d4446092e2c99d3ad7ffbf39adb1757c282f4ac7bc2407132882311e3c1e"
    family = "unknown"
    file_name = "temp.hta"
    file_type = "hta"
    first_seen = "2026-10-05 05:18:45"
  condition:
    hash.sha256(0, filesize) == "dad6d4446092e2c99d3ad7ffbf39adb1757c282f4ac7bc2407132882311e3c1e"
}
```

### Sample 6: `d25a9db2c0a77a8a`

| Field | Value |
|---|---|
| SHA-256 | `d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754` |
| Family label | `Mirai` |
| File name | `d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754` |
| File type | `elf` |
| First seen | `2026-10-05 05:17:16` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6486f00a7e4b6be37fc28a77d4ec2269` |
| SHA-1 | `c2773d1766680b714b78200590fb11946a2cadee` |
| SHA-256 | `d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754` |
| SHA3-384 | `b7dc57910dacd969b0f6dae865679f12946a44ca72aec654d4bdbc312419910c350b41d45db4c1c1bbaf6c0867a15e0e` |
| TLSH | `T1E5543A8AFD81AE25D5C122BBFE2F428A331317B8D2EB71129D145F2476CA94F0F7A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_d25a9db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754"
    family = "Mirai"
    file_name = "d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754"
    file_type = "elf"
    first_seen = "2026-10-05 05:17:16"
  condition:
    hash.sha256(0, filesize) == "d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754"
}
```

### Sample 7: `af1615e256d08472`

| Field | Value |
|---|---|
| SHA-256 | `af1615e256d0847216db684529c49c5edd93bc86960c9df82258ba2255447b1f` |
| Family label | `unknown` |
| File name | `ps_s1zdQ12P3Oik_1791176539862.ps1` |
| File type | `ps1` |
| First seen | `2026-10-05 05:14:49` |
| Reporter | `KodaDr` |
| Tags | `Formbook, Loader, PowerShell, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbfc72c4fadde04742ec7a5fecbe27b2` |
| SHA-1 | `484dfefb1298fb558c519681a06be9d11462f7c0` |
| SHA-256 | `af1615e256d0847216db684529c49c5edd93bc86960c9df82258ba2255447b1f` |
| SHA3-384 | `d712e9422f9cf995e6677ae65bc4691476aebdedea43f8af30bb237908c0e8329c172fea3b31aab0d9a2fb851c18d238` |
| TLSH | `T1F7752378445D66DB0B01B2B6FA7EB84431ED23CB8DC2121A53DCC66233E9A68537BD35` |
| SSDEEP | `24576:CsczWGndDEkz7HRWa5McftDDJe4r4fB8NcrryMvp6aF86kTet3riYgxwxdpOOeLW:CscpCkN9ftDDEK4fAUr1BwDyuacyr59` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_af1615e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af1615e256d0847216db684529c49c5edd93bc86960c9df82258ba2255447b1f"
    family = "unknown"
    file_name = "ps_s1zdQ12P3Oik_1791176539862.ps1"
    file_type = "ps1"
    first_seen = "2026-10-05 05:14:49"
  condition:
    hash.sha256(0, filesize) == "af1615e256d0847216db684529c49c5edd93bc86960c9df82258ba2255447b1f"
}
```

### Sample 8: `643f1129eb68d2ba`

| Field | Value |
|---|---|
| SHA-256 | `643f1129eb68d2ba93306bdf17ed1636d81de9f95b2a57a6ea7ed942565247db` |
| Family label | `unknown` |
| File name | `ttt.hta` |
| File type | `hta` |
| First seen | `2026-10-05 05:14:44` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44551e2b6b3c049cdc0411f4d9b29bd2` |
| SHA-1 | `7fd3c4ecc133e2e71f925d47d6c6c1069199d52f` |
| SHA-256 | `643f1129eb68d2ba93306bdf17ed1636d81de9f95b2a57a6ea7ed942565247db` |
| SHA3-384 | `d4fbe1994b98bd578185dc4e2bce3eb00e1150ab5cee8dc14f59779197e2dbdd5c1d0361a6ff23c1b7003a3812377234` |
| TLSH | `T1FF42085CAE9161B4FB1707DEB3AF28690228A0C7240DC484F54CDEE87F46BDC8A57B56` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxz8fbqFtCLSbRUM:sXX+/DV7k/38WFtPRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_643f1129
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "643f1129eb68d2ba93306bdf17ed1636d81de9f95b2a57a6ea7ed942565247db"
    family = "unknown"
    file_name = "ttt.hta"
    file_type = "hta"
    first_seen = "2026-10-05 05:14:44"
  condition:
    hash.sha256(0, filesize) == "643f1129eb68d2ba93306bdf17ed1636d81de9f95b2a57a6ea7ed942565247db"
}
```

### Sample 9: `c3d3575f71a08110`

| Field | Value |
|---|---|
| SHA-256 | `c3d3575f71a08110a2131bd27ddbf07fd86fec364d91895460b02c19c12db83b` |
| Family label | `unknown` |
| File name | `платеж № 0086.pdf.js` |
| File type | `js` |
| First seen | `2026-10-05 05:14:04` |
| Reporter | `KodaDr` |
| Tags | `Dropper, Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6725eb27534cde40431bb5438dfcf0c9` |
| SHA-1 | `a0fa73b54093167149d125a3c9ef58d85c812ca7` |
| SHA-256 | `c3d3575f71a08110a2131bd27ddbf07fd86fec364d91895460b02c19c12db83b` |
| SHA3-384 | `110aa07867e92516ea92a0a49b4c1633ecdae0ec5de852c3f36a5656817b4949fd3c1843a9844056350758629eb2babc` |
| TLSH | `T1BFA5F15488D03FE8DB76561880FD962DE3B10A9B4C2E694AB73FBD45EFB7500C2061DA` |
| SSDEEP | `24576:SXwfIFVl195nHw9XFHXt6di+q2FLfUkSibjNudH4tmt+n43Y6ipC1ACuQhmj+mNf:HUVfsFgk+lNUdi3QH4tq4VxG5dhTE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_c3d3575f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3d3575f71a08110a2131bd27ddbf07fd86fec364d91895460b02c19c12db83b"
    family = "unknown"
    file_name = "платеж № 0086.pdf.js"
    file_type = "js"
    first_seen = "2026-10-05 05:14:04"
  condition:
    hash.sha256(0, filesize) == "c3d3575f71a08110a2131bd27ddbf07fd86fec364d91895460b02c19c12db83b"
}
```

### Sample 10: `cb06b7dc4bcdf7ce`

| Field | Value |
|---|---|
| SHA-256 | `cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d` |
| Family label | `Mirai` |
| File name | `cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d` |
| File type | `elf` |
| First seen | `2026-10-05 04:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecb217c6549b5fdd8d411abe5b1d685f` |
| SHA-1 | `d9f4d3905c250c72ec2f644050412f17beb70f01` |
| SHA-256 | `cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d` |
| SHA3-384 | `867d19cb4be1a97aecaa8024c271ae9c9b605354720af314b281f15610285e6dc0590cb829cae09174374595055f2c4e` |
| TLSH | `T187F3199EFD81EE6546C127BBFE2E418A331317B4D2EB71129D141F2876CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnw3:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_cb06b7dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d"
    family = "Mirai"
    file_name = "cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d"
    file_type = "elf"
    first_seen = "2026-10-05 04:17:14"
  condition:
    hash.sha256(0, filesize) == "cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d"
}
```

### Sample 11: `a61ba4f611fc68f3`

| Field | Value |
|---|---|
| SHA-256 | `a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9` |
| Family label | `VShell` |
| File name | `a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9.exe` |
| File type | `exe` |
| First seen | `2026-10-05 04:13:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cec4f5da1c578aa3a9e08523ca436aea` |
| SHA-1 | `48fe88c9b066b832a37d600dff06ed2477ac781b` |
| SHA-256 | `a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9` |
| SHA3-384 | `581a24652e5c079b6192d1fccbcc03683944423f65f584a0791a332550172cdd94b97c822818fbb38515d180a5e7e4bf` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T136715088F3136EF1E42C46F901D3A664D0199BBCC150BF4D5E60281D3C210BA259AF96` |
| SSDEEP | `48:6Icwm03t2WVJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4j+tnSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_011_a61ba4f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9"
    family = "VShell"
    file_name = "a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9.exe"
    file_type = "exe"
    first_seen = "2026-10-05 04:13:52"
  condition:
    hash.sha256(0, filesize) == "a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9"
}
```

### Sample 12: `c63226d1962d07fc`

| Field | Value |
|---|---|
| SHA-256 | `c63226d1962d07fcb5303ca2b8e0d82aa6468aed86050197db502525654cf095` |
| Family label | `Mirai` |
| File name | `jack5tr.sh` |
| File type | `sh` |
| First seen | `2026-10-05 04:04:53` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0928a69daa25639b899378db05356515` |
| SHA-1 | `fd2cc3e15045a422e5ac1d64a9e5b4c3e257770f` |
| SHA-256 | `c63226d1962d07fcb5303ca2b8e0d82aa6468aed86050197db502525654cf095` |
| SHA3-384 | `26aa8b28900e519f05ee31dacee620edbe92a8ec07a41aad4b8b5fed66846c1b4caf6807097081815f234254f014b73d` |
| TLSH | `T14D4160CA2092A5B6ACAADD77B26DC94471C4B0C351CE7E0DECDC39E9C5DEE40B144B62` |
| SSDEEP | `48:HKppwipGRGQpnjNp+s6pBNnBb7pddpuyupHRHCQpJ+o+p8KEpLIOpbFpI2:HKoiYQQNNZ6LjvB8VdNHn+dEDLB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_c63226d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c63226d1962d07fcb5303ca2b8e0d82aa6468aed86050197db502525654cf095"
    family = "Mirai"
    file_name = "jack5tr.sh"
    file_type = "sh"
    first_seen = "2026-10-05 04:04:53"
  condition:
    hash.sha256(0, filesize) == "c63226d1962d07fcb5303ca2b8e0d82aa6468aed86050197db502525654cf095"
}
```

### Sample 13: `36a048b70f0add87`

| Field | Value |
|---|---|
| SHA-256 | `36a048b70f0add874047b8b9e794182497fe7a0580e9a0a4eb3638cbf0111a21` |
| Family label | `unknown` |
| File name | `eclipse.sh` |
| File type | `sh` |
| First seen | `2026-10-05 04:00:11` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4966fba1bf680fb14165db4c4348698` |
| SHA-1 | `679b197757b9727eb101e4e7eaee6510e216205f` |
| SHA-256 | `36a048b70f0add874047b8b9e794182497fe7a0580e9a0a4eb3638cbf0111a21` |
| SHA3-384 | `12b3674922f7074258573db2dea365d3265e3db174e1cbad21a108235cadde98808c80edc2eca1fcecde1663c2b48f8b` |
| TLSH | `T130C08CDF0024457CAC85E009BA4A04E2A080806A268A6D2888452C7FD85910EB05AAB4` |
| SSDEEP | `3:TKH4vGBwVLJJ4kO2Qi6LkXpFZTLTeUWciTqPuBNbIg1EIAUzOdGEZWJAwjVZLKn:hDrKiLpzfWxqG7bIgSZwpOwe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_36a048b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36a048b70f0add874047b8b9e794182497fe7a0580e9a0a4eb3638cbf0111a21"
    family = "unknown"
    file_name = "eclipse.sh"
    file_type = "sh"
    first_seen = "2026-10-05 04:00:11"
  condition:
    hash.sha256(0, filesize) == "36a048b70f0add874047b8b9e794182497fe7a0580e9a0a4eb3638cbf0111a21"
}
```

### Sample 14: `1d6fd65e639d9a3a`

| Field | Value |
|---|---|
| SHA-256 | `1d6fd65e639d9a3ac93a8c15bf2d39f518b27ff34bbb8b806fc16a1435948a7f` |
| Family label | `Mirai` |
| File name | `eclipse.mips` |
| File type | `elf` |
| First seen | `2026-10-05 04:00:09` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95605d0f16c43ed9bdad067ef603e247` |
| SHA-1 | `18f818c32fa94da59de206a4255cae7f95fb6cbf` |
| SHA-256 | `1d6fd65e639d9a3ac93a8c15bf2d39f518b27ff34bbb8b806fc16a1435948a7f` |
| SHA3-384 | `dfdbdb312bdf59bcb7051640c19d2019fbd206110fc2fc76b3b8c857ecb43c71dad1de085ee8a717dbd95ce2a5ff77ce` |
| TLSH | `T1BE04541A3E22DFBBF56D827047F78930569876D636E19684F16CD71C1E2028E241FBE8` |
| TELFHASH | `t1424160180e7813f0a7355c4d19ddff37a2a330eb7a125c378e11e86aab698834d10c1c` |
| SSDEEP | `3072:piijwIbzMz69kWMM6fGq++Yft7/tMmejIxfQ2Ru7XY:8ijwIbzMAT6ObBfx/zejgL+Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_1d6fd65e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d6fd65e639d9a3ac93a8c15bf2d39f518b27ff34bbb8b806fc16a1435948a7f"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-10-05 04:00:09"
  condition:
    hash.sha256(0, filesize) == "1d6fd65e639d9a3ac93a8c15bf2d39f518b27ff34bbb8b806fc16a1435948a7f"
}
```

### Sample 15: `3baf1b9349f0b271`

| Field | Value |
|---|---|
| SHA-256 | `3baf1b9349f0b271860e300c2e61f34a3ea0ceed25e518b08db9274a730eabc9` |
| Family label | `Mirai` |
| File name | `eclipse.x86_64` |
| File type | `elf` |
| First seen | `2026-10-05 04:00:06` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e727f9d15f9db77d80a7bb0d902225e` |
| SHA-1 | `5856d9f25547e1b6340caa89feef8dcee4c48e1d` |
| SHA-256 | `3baf1b9349f0b271860e300c2e61f34a3ea0ceed25e518b08db9274a730eabc9` |
| SHA3-384 | `e3614c833c6b0b2b5b02b52d427c89bc9dd28f602d54964e8b6dadc0915d36ab7f10513f242dc955e85b56e33e64685c` |
| TLSH | `T160356C5AF2F370BCD067C030439BDB62A835F47901226E7B65C4DA352D66EA01B29F67` |
| TELFHASH | `t1d8c18a708af575b0a7d7cd50b362f075aa72547a66e93af11a13adc4ef00f804c9682f` |
| SSDEEP | `12288:8F/4HH4fUGYmeOzuWVYjgQooRs/mBD/HNDFmyObD+pndCuMu/5k:8F/qH4fU4jzuWVYjVoWsOF/Fy+BdSu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_3baf1b93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3baf1b9349f0b271860e300c2e61f34a3ea0ceed25e518b08db9274a730eabc9"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-10-05 04:00:06"
  condition:
    hash.sha256(0, filesize) == "3baf1b9349f0b271860e300c2e61f34a3ea0ceed25e518b08db9274a730eabc9"
}
```

### Sample 16: `ffa91bd5a14c9171`

| Field | Value |
|---|---|
| SHA-256 | `ffa91bd5a14c9171559048f3f5bb6e76d9224e106de839c13dbf4843c313e763` |
| Family label | `unknown` |
| File name | `eclipse.mipsel` |
| File type | `elf` |
| First seen | `2026-10-05 04:00:04` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `499e5d99e15aebf69877ee76bdafe6f4` |
| SHA-1 | `d17e6e19f2fca9e02c717434e108684362191f5e` |
| SHA-256 | `ffa91bd5a14c9171559048f3f5bb6e76d9224e106de839c13dbf4843c313e763` |
| SHA3-384 | `105d68bea190302e6c7caae5e5f53bf9577108b12b6d88bf0f582f40796e6f03f726823920bb139fad7ce490e5b42faf` |
| TLSH | `T13D04C507AB519EF7C86FDC7306F98A0124CCF4572664377A3274DA6CBA1A58B05E3CA4` |
| SSDEEP | `3072:QhkgHidRHGKAmL1YrtvvjfJ/mvmGdER7xdEH:QhkYKZ1YrJfAvmG8TEH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_ffa91bd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffa91bd5a14c9171559048f3f5bb6e76d9224e106de839c13dbf4843c313e763"
    family = "unknown"
    file_name = "eclipse.mipsel"
    file_type = "elf"
    first_seen = "2026-10-05 04:00:04"
  condition:
    hash.sha256(0, filesize) == "ffa91bd5a14c9171559048f3f5bb6e76d9224e106de839c13dbf4843c313e763"
}
```

### Sample 17: `46db514c0791f409`

| Field | Value |
|---|---|
| SHA-256 | `46db514c0791f4093050cad13f69dd6cf207887992104b57ba3bca38d38ba14c` |
| Family label | `Gafgyt` |
| File name | `46db514c0791f409.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:25:37` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8d669b637b41c45aefca1d5f66ed368` |
| SHA-1 | `b1d17eb9fa275c364d76dbc630ea50455c00ef86` |
| SHA-256 | `46db514c0791f4093050cad13f69dd6cf207887992104b57ba3bca38d38ba14c` |
| SHA3-384 | `a8a2467b9be371ebe5ca8c1285b21688243fd211eb1cd88a545fa4ba6b0fbbbb7792aa4f7f51c261d3964f1152073c7e` |
| TLSH | `T1D464C716BB919EF7C85ECD3306EA4A1110CCE44622A56B2BB7B8C61CF74B94F48E3D54` |
| TELFHASH | `t1e6612204a43d09d9de231c196c686ff35957e52a32e6bb28ff1addc0084e428f158e0f` |
| SSDEEP | `6144:cU+L9NDu4D/fj6Fvi1FihvZHtWGL5Fh5J/qOAYP:chDyk2FvimhvZHtWGL5Fh5J/qOAYP` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_017_46db514c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46db514c0791f4093050cad13f69dd6cf207887992104b57ba3bca38d38ba14c"
    family = "Gafgyt"
    file_name = "46db514c0791f409.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:37"
  condition:
    hash.sha256(0, filesize) == "46db514c0791f4093050cad13f69dd6cf207887992104b57ba3bca38d38ba14c"
}
```

### Sample 18: `f7a1fa3463a54874`

| Field | Value |
|---|---|
| SHA-256 | `f7a1fa3463a548743ef3748dad33f678356bd659405e4f412d85cdabb9929e45` |
| Family label | `Gafgyt` |
| File name | `f7a1fa3463a54874.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:25:28` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `146ca25c64421c93d0896ca815670f52` |
| SHA-1 | `f54a676ddc95fb0912a816fb44d63400ccd2e351` |
| SHA-256 | `f7a1fa3463a548743ef3748dad33f678356bd659405e4f412d85cdabb9929e45` |
| SHA3-384 | `04229c5c77b8438dd612c839d177fe3aaf6b4e9a490f244d30e432343a2c8822e74064d32bf0a26393dff267a96b48bc` |
| TLSH | `T1B0544B05EA408F5BC1D1177ABB9F425D33339F6893DB73029A24AB742BC6BAD1E39111` |
| TELFHASH | `t13c611044a43d09dade631c19ac686fb34557e62a32e6bb68ff1addc0084e429f158d0f` |
| SSDEEP | `6144:jeFNHB+yOWXuVc8adFn3PjV5zcGOmumTcCXYk+2myz5c7yZGVLmxUNt:R0Xx8adJLV5zcrme32myz5c7yIVLmxUz` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_018_f7a1fa34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a1fa3463a548743ef3748dad33f678356bd659405e4f412d85cdabb9929e45"
    family = "Gafgyt"
    file_name = "f7a1fa3463a54874.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:28"
  condition:
    hash.sha256(0, filesize) == "f7a1fa3463a548743ef3748dad33f678356bd659405e4f412d85cdabb9929e45"
}
```

### Sample 19: `35d2c3464b1b345e`

| Field | Value |
|---|---|
| SHA-256 | `35d2c3464b1b345e0bf5711b845abd988435bb2da9b452a0de44f99745f3d62c` |
| Family label | `Gafgyt` |
| File name | `35d2c3464b1b345e.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:25:19` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22b905a10e07e3a984ed85393ea7f93f` |
| SHA-1 | `27ad19418ad9e538b0008c495f7011306e760a12` |
| SHA-256 | `35d2c3464b1b345e0bf5711b845abd988435bb2da9b452a0de44f99745f3d62c` |
| SHA3-384 | `86de8e2e7f0a6040f80c6a51cc185557f95cf2831e748e5e88dc4af712de0a2e7e42c5fc599024638123089cccb884ea` |
| TLSH | `T155342A05FC504B6BC6D32BBBFB8E428D37336B5897DB73019A24AE702B8679D1D29111` |
| TELFHASH | `t1e6612204a43d09d9de231c196c686ff35957e52a32e6bb28ff1addc0084e428f158e0f` |
| SSDEEP | `6144:Ag+C/uRpq/Yq/QXyMXMq2Fg74swOTNBlK4qKjaMv9dZHlWZgs67ojz3VbO:LWCU74sP3I48Mv9dZHlWms67ojz3VbO` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_019_35d2c346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d2c3464b1b345e0bf5711b845abd988435bb2da9b452a0de44f99745f3d62c"
    family = "Gafgyt"
    file_name = "35d2c3464b1b345e.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:19"
  condition:
    hash.sha256(0, filesize) == "35d2c3464b1b345e0bf5711b845abd988435bb2da9b452a0de44f99745f3d62c"
}
```

### Sample 20: `2bfc0f1dbec327a2`

| Field | Value |
|---|---|
| SHA-256 | `2bfc0f1dbec327a29e9fd26ba97dde795ae768382cb64ffecf694a111483cc6a` |
| Family label | `Gafgyt` |
| File name | `2bfc0f1dbec327a2.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:25:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e65dd5d99f3e2edbad42e408b7eb529` |
| SHA-1 | `c9e6884009d8005b741a0d2f12fca5f9d24a409e` |
| SHA-256 | `2bfc0f1dbec327a29e9fd26ba97dde795ae768382cb64ffecf694a111483cc6a` |
| SHA3-384 | `7f083aed795ba710527db36f7e0b56485266f314caa31234d15438c666dbb424bb91d2078d14c2fcc23e155a80c22bf1` |
| TLSH | `T172343A05FC548B6BC6D22BBBFB8E428D37335B5897DB33019A246E742BC6B9D1D29101` |
| TELFHASH | `t1e6612204a43d09d9de231c196c686ff35957e52a32e6bb28ff1addc0084e428f158e0f` |
| SSDEEP | `6144:CC/ITqq/3q/xL5oLk8Pb4a6oIa8xPnchK56uEvgdZHYlZSjHNH2UsMOO:TlUb4a/QtncUyvgdZHYlsjHNH2UsMOO` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_020_2bfc0f1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bfc0f1dbec327a29e9fd26ba97dde795ae768382cb64ffecf694a111483cc6a"
    family = "Gafgyt"
    file_name = "2bfc0f1dbec327a2.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:10"
  condition:
    hash.sha256(0, filesize) == "2bfc0f1dbec327a29e9fd26ba97dde795ae768382cb64ffecf694a111483cc6a"
}
```

### Sample 21: `da6a531b019998fd`

| Field | Value |
|---|---|
| SHA-256 | `da6a531b019998fd3e7340998e756ea9cf7ea6974f2df0770b67fed55bddedf8` |
| Family label | `Gafgyt` |
| File name | `da6a531b019998fd.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:25:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0cb647db850d6d1c3d582ea9ea769fe` |
| SHA-1 | `d4fb2cb94995256d5ffbf1170417703cc0288807` |
| SHA-256 | `da6a531b019998fd3e7340998e756ea9cf7ea6974f2df0770b67fed55bddedf8` |
| SHA3-384 | `7c66118d5a2e313fc6fe323df9315020f7e467ce2b62254bcdd282aae314ef2d50433d0125cdc9216e3487996fbd5a00` |
| TLSH | `T1A664C72A7A21EF7FE17887310BF78B74839521D62BE19746E16CC31C1E6028D585FBA4` |
| TELFHASH | `t1e6612204a43d09d9de231c196c686ff35957e52a32e6bb28ff1addc0084e428f158e0f` |
| SSDEEP | `6144:7VpbM8I3dnwI0NeSd9i/TQboWI1v5lhvYHtWGL5Fh5J/qOAYP:bIN+eSdvIB5lhvYHtWGL5Fh5J/qOAYP` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_021_da6a531b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da6a531b019998fd3e7340998e756ea9cf7ea6974f2df0770b67fed55bddedf8"
    family = "Gafgyt"
    file_name = "da6a531b019998fd.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:01"
  condition:
    hash.sha256(0, filesize) == "da6a531b019998fd3e7340998e756ea9cf7ea6974f2df0770b67fed55bddedf8"
}
```

### Sample 22: `0b44e0e5640696e0`

| Field | Value |
|---|---|
| SHA-256 | `0b44e0e5640696e069413aebe9ba4c1f116f51b79277e27a9827addb5a3b5b74` |
| Family label | `Mirai` |
| File name | `0b44e0e5640696e0.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:24:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e83733b322a605a96a68d386046e2fb0` |
| SHA-1 | `94c7395bc5a16b4a3abcc2af3a12244507ee00c7` |
| SHA-256 | `0b44e0e5640696e069413aebe9ba4c1f116f51b79277e27a9827addb5a3b5b74` |
| SHA3-384 | `aeeb2ecc2503389c0d9480edce42668cabafe0ad0e50b742aa7f6a24f44270c6062bf77392cbbac9f5d7709cdaeb9120` |
| TLSH | `T14F344A47A9E08FBBC146AF7165B35A34071BE8161F4B0F9BA539E5B4524B8CDF00AB34` |
| TELFHASH | `t151612205a43d09d9de231c196c686ff35957e52a32e6bb28ff1addc0084e428f158d0f` |
| SSDEEP | `6144:OQyJ+S0f4yuKHYnB9lSRh0YmvjPwYLqz0hxmyGklpO:OQlS0Qyu/B/q+3vjPwYLqz0hxmyGklpO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_0b44e0e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b44e0e5640696e069413aebe9ba4c1f116f51b79277e27a9827addb5a3b5b74"
    family = "Mirai"
    file_name = "0b44e0e5640696e0.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:24:52"
  condition:
    hash.sha256(0, filesize) == "0b44e0e5640696e069413aebe9ba4c1f116f51b79277e27a9827addb5a3b5b74"
}
```

### Sample 23: `3c29f43472e65ea1`

| Field | Value |
|---|---|
| SHA-256 | `3c29f43472e65ea111cf6fa376ba1bd7e3d4bf3e1d2f05d44456d08b16ea1934` |
| Family label | `Mirai` |
| File name | `3c29f43472e65ea1.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:24:43` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c9accd6d19254c49bb564e43b43bf6e` |
| SHA-1 | `0220e8a6fc38e4f2a0e43eadb3b9c096be4ed2f3` |
| SHA-256 | `3c29f43472e65ea111cf6fa376ba1bd7e3d4bf3e1d2f05d44456d08b16ea1934` |
| SHA3-384 | `512081516746226b19ad6b7f6335f04d70fb1ecefec2d500c8972e51206df07ef09fb36603851ce1b301fe8ff73b7e50` |
| TLSH | `T177442B08EE408B5BC5E237B9FB8F424A33339B58A7E7730596285BB437C7B595E25102` |
| TELFHASH | `t1ce311246a53d856a5e612c18cd2c6fb2141b8b233252ba35ff09dcc5682e402f928d0f` |
| SSDEEP | `6144:xj3lLC2pMdIw6rEa+OiFqq/EpSJHc7Og1liIgEV/Gf7md28gvIgS:xd+Sw6rEa+rqq/+yc7Og1N/g7mdFgvIn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_3c29f434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c29f43472e65ea111cf6fa376ba1bd7e3d4bf3e1d2f05d44456d08b16ea1934"
    family = "Mirai"
    file_name = "3c29f43472e65ea1.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:24:43"
  condition:
    hash.sha256(0, filesize) == "3c29f43472e65ea111cf6fa376ba1bd7e3d4bf3e1d2f05d44456d08b16ea1934"
}
```

### Sample 24: `d624722887c94f66`

| Field | Value |
|---|---|
| SHA-256 | `d624722887c94f66e81a1f12bbb881baa2a95d31c346f3fae2f6dbb6b0fccaa9` |
| Family label | `unknown` |
| File name | `d624722887c94f66.bin` |
| File type | `elf` |
| First seen | `2026-10-05 03:24:35` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cade129458e5fc51ce1abbefd6fe388` |
| SHA-1 | `4f82458c6cb8201ae1d9ee00e70cd0758cf195d3` |
| SHA-256 | `d624722887c94f66e81a1f12bbb881baa2a95d31c346f3fae2f6dbb6b0fccaa9` |
| SHA3-384 | `8e7744f7a113c26ea7bbc26c12d562feff65263ed643de9fff37f48b1d2c16eb2f29137432b2d182ea256d384bb1de63` |
| TLSH | `T1F8243A0775E0C9FBC4C69BB56BDB95228933F4392B32620A73D8BDA52F0DAD46D1D210` |
| TELFHASH | `t1fc612204a43d09d9de231c196c686ff35957e62a32e6bb28ff1addc0084e429f158e0f` |
| SSDEEP | `6144:NueuOLIuFR8aLJn9v2dZreLjL/+n2ckJpO:Nueu2R8I9v2dZreLjL/+n2ckJpO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_d6247228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d624722887c94f66e81a1f12bbb881baa2a95d31c346f3fae2f6dbb6b0fccaa9"
    family = "unknown"
    file_name = "d624722887c94f66.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:24:35"
  condition:
    hash.sha256(0, filesize) == "d624722887c94f66e81a1f12bbb881baa2a95d31c346f3fae2f6dbb6b0fccaa9"
}
```

### Sample 25: `9ea606cb554ea1f8`

| Field | Value |
|---|---|
| SHA-256 | `9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671` |
| Family label | `Mirai` |
| File name | `9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671` |
| File type | `elf` |
| First seen | `2026-10-05 03:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68c87fde0119f7c64fba8e4234d6ae88` |
| SHA-1 | `13a65a7245a2aba0e08dce11cefd69c3597ab383` |
| SHA-256 | `9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671` |
| SHA3-384 | `82c852bb7d3758f52da1dc31f53f15bb986f401b9dae4e0ef08383c4a7d2276fa6f963d682de916ad3e8eac6307da115` |
| TLSH | `T187E3199EFD81EE6546C127BBFE2E418A331317B4D2EB71129D141F2876CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwZ:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_9ea606cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671"
    family = "Mirai"
    file_name = "9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671"
    file_type = "elf"
    first_seen = "2026-10-05 03:17:14"
  condition:
    hash.sha256(0, filesize) == "9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671"
}
```

### Sample 26: `6d69d14d77978195`

| Field | Value |
|---|---|
| SHA-256 | `6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b` |
| Family label | `WannaCry` |
| File name | `6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b` |
| File type | `exe` |
| First seen | `2026-10-05 03:15:42` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60ab33b01081d37beeeb3c62ae8e3333` |
| SHA-1 | `4965d46257b87fec0f130efce1fe600eae65a70c` |
| SHA-256 | `6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b` |
| SHA3-384 | `617416cbb4aa4d7cbb9d66ee163bfb618e1001943ca5e815986b4ada0a1207f1743dc980371fc77c9d90a447e130bcd6` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1133633D471A890F8E1020AB488B74E15F7B77C3923B75E0FAB804A7A1E53F97A754352` |
| SSDEEP | `98304:D59PoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2H:D59Pe1Cxcxk3ZAEUadzR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_026_6d69d14d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b"
    family = "WannaCry"
    file_name = "6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b"
    file_type = "exe"
    first_seen = "2026-10-05 03:15:42"
  condition:
    hash.sha256(0, filesize) == "6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b"
}
```

### Sample 27: `f5c8298c37963b6d`

| Field | Value |
|---|---|
| SHA-256 | `f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93` |
| Family label | `unknown` |
| File name | `f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93.bin` |
| File type | `apk` |
| First seen | `2026-10-05 03:13:51` |
| Reporter | `Tuxxin` |
| Tags | `apk, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f88c7b63d6beff89c4fe04a0f45a2a11` |
| SHA-1 | `dc805d894bbd31ceda0b1e61bb97450eaf5d1a46` |
| SHA-256 | `f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93` |
| SHA3-384 | `228fa75ed014da5036957152eefcbd89c7ca43b518af6de89158ae83c130135348ed4a57d55decb71a169595c3d4a77b` |
| TLSH | `T103072352FBE89E1ECC7381351F4A5235111AAE23C792D34BD968339C38B76E40E467E9` |
| SSDEEP | `393216:Ov+P5ymhhVaoMMom3QFnebb1jD2ND19E2GlZYn:urmhjR6m3QFne1jH2GlGn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_f5c8298c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93"
    family = "unknown"
    file_name = "f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93.bin"
    file_type = "apk"
    first_seen = "2026-10-05 03:13:51"
  condition:
    hash.sha256(0, filesize) == "f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93"
}
```

### Sample 28: `75eec3fe903f215c`

| Field | Value |
|---|---|
| SHA-256 | `75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0` |
| Family label | `VShell` |
| File name | `75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0.exe` |
| File type | `exe` |
| First seen | `2026-10-05 03:13:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c575d4e54baf181f44271cacd0618eb` |
| SHA-1 | `9f411adee1ebc8333ee2f3db35cd76136a84ffa6` |
| SHA-256 | `75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0` |
| SHA3-384 | `e2f6f20c1069ea4ae437553e516a3dbdf6c2f230a81911ff83e4116709fab3418f9211de7b69ac44ed241a947f149c9a` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17291D84170B999E7E85C51BF4C0FB494B919740A41C483B70378A5993E3957BF47CB0D` |
| SSDEEP | `48:6IIF9BlQaexgflgZH7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMg4M0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_028_75eec3fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0"
    family = "VShell"
    file_name = "75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0.exe"
    file_type = "exe"
    first_seen = "2026-10-05 03:13:41"
  condition:
    hash.sha256(0, filesize) == "75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0"
}
```

### Sample 29: `576fe0330127a7b3`

| Field | Value |
|---|---|
| SHA-256 | `576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462` |
| Family label | `Mirai` |
| File name | `576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462.elf` |
| File type | `elf` |
| First seen | `2026-10-05 02:54:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39e06eab7a3278472831b788f6efdd3d` |
| SHA-1 | `e4f8e4dcfcaad0f26059ac174e7e44299eb90ac9` |
| SHA-256 | `576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462` |
| SHA3-384 | `2adfe49e0d843edf1a03d3c252a4e3f0693773b2d3fd8cc6de1244ad420e1bbc8b3666228d671430b5764adfb6e190ae` |
| TLSH | `T1A2144957F1129E81F14206F4256DC7F03F12A5E723372CA1E9BB82F95B4389ABC15B62` |
| SSDEEP | `3072:vvxg2TRLEUbKvgXGeSUB/41WLBc8xOUq:32ARLEnvg2eSUp41Wi8xOUq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_576fe033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462"
    family = "Mirai"
    file_name = "576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462.elf"
    file_type = "elf"
    first_seen = "2026-10-05 02:54:56"
  condition:
    hash.sha256(0, filesize) == "576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462"
}
```

### Sample 30: `fb7460f1febcc0f1`

| Field | Value |
|---|---|
| SHA-256 | `fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e` |
| Family label | `CoinMiner` |
| File name | `fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e.exe` |
| File type | `exe` |
| First seen | `2026-10-05 02:35:44` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8de4f7dc19cf7f78385e3cbb5b31a684` |
| SHA-1 | `4f1cf8799aca04e99ebce7553a3042ae29706f00` |
| SHA-256 | `fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e` |
| SHA3-384 | `1814b69ccc3e78eea2ce1102f788029880a939c7576d8d5934fb620cbdd31ee2f3a48e2e6db9111f1688af9ad54617c1` |
| IMPHASH | `2f395dd587b12a61e6877a545da7a7d8` |
| TLSH | `T16F172315B79724EFCA168234187EA720FE6EDAA46245CB7B879CC27C3D72C6918C43D1` |
| SSDEEP | `393216:ySiO33nWRq4q1bHqzekMosMGbZqzFRq4EJix33nII:viO33nWRqt1bwekfsTb+FRqZJix33nII` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_030_fb7460f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e"
    family = "CoinMiner"
    file_name = "fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e.exe"
    file_type = "exe"
    first_seen = "2026-10-05 02:35:44"
  condition:
    hash.sha256(0, filesize) == "fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e"
}
```

### Sample 31: `ed07f823263ca2ff`

| Field | Value |
|---|---|
| SHA-256 | `ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745` |
| Family label | `PythonStealer` |
| File name | `ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745.exe` |
| File type | `exe` |
| First seen | `2026-10-05 02:23:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, PythonStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a5e9b41b7d6b1edb066ecb2f4268c19` |
| SHA-1 | `205067a7b165ba250b0b8c668e016d4ffed914c3` |
| SHA-256 | `ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745` |
| SHA3-384 | `7fb9a2e5928dfb5bd1a9320fe7a5974ef6025d05b8c730e322cb7627ea42912769d72e5ee7d3b6e43b2f87ffd7fac96a` |
| IMPHASH | `3f7419dcd097c9ef0b7fe5300f39861d` |
| TLSH | `T1B7F6330D75902086C20AD1B926EECE1264B2B6970B7605DF2BE1FFA01D75BE3152F739` |
| SSDEEP | `393216:qe3Xtky920T5E4j6LodxpP/Z6l3YSpmNKlzJd:qeKy9p555dx9/Z6l3YSamzJd` |
| ICON-DHASH | `8023f0b2b2f02b82` |

#### Technical Assessment

- The sample is tracked as `PythonStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PythonStealer_031_ed07f823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745"
    family = "PythonStealer"
    file_name = "ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745.exe"
    file_type = "exe"
    first_seen = "2026-10-05 02:23:47"
  condition:
    hash.sha256(0, filesize) == "ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745"
}
```

### Sample 32: `0ea91c691e0e6cab`

| Field | Value |
|---|---|
| SHA-256 | `0ea91c691e0e6cabb40dbe214b536081c9b4ca2012927fea88fb40b33bfd42df` |
| Family label | `unknown` |
| File name | `fuck_niggers_39.hta` |
| File type | `hta` |
| First seen | `2026-10-05 02:22:20` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2de00de1930300f394722fd91f0243b` |
| SHA-1 | `9c422428e33a05c009dfa02f5496e757f1bf15cf` |
| SHA-256 | `0ea91c691e0e6cabb40dbe214b536081c9b4ca2012927fea88fb40b33bfd42df` |
| SHA3-384 | `515a2dd041a64949675c72864811e589827b0df13fb7185cad3861e845ef584f2a68804d3631d8c9bd7e9d19c8243bed` |
| TLSH | `T15D421A5CAED1B2B0EA1703DE77AF28690228A0C7600DC484F94CDEE47F46BDD4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzPbqFtCQSxjRUM:sXX+/DV7k/3mFtuRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_0ea91c69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ea91c691e0e6cabb40dbe214b536081c9b4ca2012927fea88fb40b33bfd42df"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-10-05 02:22:20"
  condition:
    hash.sha256(0, filesize) == "0ea91c691e0e6cabb40dbe214b536081c9b4ca2012927fea88fb40b33bfd42df"
}
```

### Sample 33: `dbe19861490e9f9b`

| Field | Value |
|---|---|
| SHA-256 | `dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008` |
| Family label | `Mirai` |
| File name | `dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008` |
| File type | `elf` |
| First seen | `2026-10-05 02:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `281050a949badc4c3cbf1ad5bd4f8f68` |
| SHA-1 | `d13ec3b1c040028d3da9da73d4bf23177db32c90` |
| SHA-256 | `dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008` |
| SHA3-384 | `05889d00a8e82afd291e820ff21ff16f1917fe37687d70c248e11a4194cae91c8c3c83a64d5d883fdbcf0dcd6b596990` |
| TLSH | `T17A530886BC828A9659C413BBB97E41CD330337B8D2DF7103DD151F18B6CA94F0E6A952` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DhrPDysX+4if3Lh:T2s/ITo7WCkybotgsJ913DhrbW4UF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_dbe19861
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008"
    family = "Mirai"
    file_name = "dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008"
    file_type = "elf"
    first_seen = "2026-10-05 02:17:14"
  condition:
    hash.sha256(0, filesize) == "dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008"
}
```

### Sample 34: `d5aa43a733cb2787`

| Field | Value |
|---|---|
| SHA-256 | `d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e` |
| Family label | `unknown` |
| File name | `d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e.dll` |
| File type | `dll` |
| First seen | `2026-10-05 01:55:55` |
| Reporter | `Kejult` |
| Tags | `dll, DLLhijack, hijack` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db899c6a07fffdec0413a99d0e2e1480` |
| SHA-1 | `39aff81e8e5fa8f2ddc7e6e845b8c622f243c3c3` |
| SHA-256 | `d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e` |
| SHA3-384 | `52683c7d6a5c060af8b91552f13ea9747a96cbbd11b4f904c123f0b757fe8bff030cab3957f9e0bc6b191091802305c7` |
| IMPHASH | `0392aa966668f99fe783c0ba6bdd509a` |
| TLSH | `T111263349BADB025DD89672704F6AFD7EB2B92CCC4204DC4DD44DE587E8B2729703A90E` |
| SSDEEP | `98304:yCMWmcKfST5t+BceThTHfaCCUqmJPCYvboB1fdmyz:BMWKfU+BcUTHCCCfqCiUffnz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_d5aa43a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e"
    family = "unknown"
    file_name = "d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e.dll"
    file_type = "dll"
    first_seen = "2026-10-05 01:55:55"
  condition:
    hash.sha256(0, filesize) == "d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e"
}
```

### Sample 35: `062aca87d292a3f4`

| Field | Value |
|---|---|
| SHA-256 | `062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d` |
| Family label | `unknown` |
| File name | `062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d.dll` |
| File type | `exe` |
| First seen | `2026-10-05 01:55:41` |
| Reporter | `Kejult` |
| Tags | `dll, DLLhijack, exe, hijack` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40e405807927ccf8a73fa7289dae1dc3` |
| SHA-1 | `61524836336dedaa6c59fee95fcf23c9d6ad0a8e` |
| SHA-256 | `062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d` |
| SHA3-384 | `2f0cab13c168a23cbfb9fe7d327c18466af31d7ac656f5d9e6549395f1760f239aa9dd2764ef708a5bf930ab7e6264e8` |
| IMPHASH | `58e683abec29a387daf56221678b4318` |
| TLSH | `T18BE523E5B6D739F6D023CBF4DA62A1AD70393F505F635C5F3B8929014E62228973A390` |
| SSDEEP | `49152:P9KpI8cBa0kj6BK0x3TiMQclkGo2PXk6rkwuuWG/+WizBedfb77N3SnKrKB+/:P9m29xx3Tiqt06ox6+z2rNNrKo/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_062aca87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d"
    family = "unknown"
    file_name = "062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d.dll"
    file_type = "exe"
    first_seen = "2026-10-05 01:55:41"
  condition:
    hash.sha256(0, filesize) == "062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d"
}
```

### Sample 36: `9fc2368188b4ea8c`

| Field | Value |
|---|---|
| SHA-256 | `9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8` |
| Family label | `unknown` |
| File name | `9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8.dll` |
| File type | `dll` |
| First seen | `2026-10-05 01:55:26` |
| Reporter | `Kejult` |
| Tags | `dll, DLLhijack, hijack` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5eebcb1963bffe782e1a4cc7703abd0` |
| SHA-1 | `4e016d2db93c9a71f42b8349c09da66b6c8bbbc7` |
| SHA-256 | `9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8` |
| SHA3-384 | `54ee4e9cd500fc49cef20faf99a456905e5bd641dd7e2118d4677ef435e339820055aa9b21e62e9e05b6be97ac9146c3` |
| IMPHASH | `0392aa966668f99fe783c0ba6bdd509a` |
| TLSH | `T19D263349BADB025DD89672704F6AFD7EB2B92CCC4204DC4DD44DE587E8B2729703A90E` |
| SSDEEP | `98304:yCMWmcKfST5t+BceThTHfaCCUqmJPCYvboB1fdmym:BMWKfU+BcUTHCCCfqCiUffnm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_9fc23681
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8"
    family = "unknown"
    file_name = "9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8.dll"
    file_type = "dll"
    first_seen = "2026-10-05 01:55:26"
  condition:
    hash.sha256(0, filesize) == "9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8"
}
```

### Sample 37: `c072653018239d92`

| Field | Value |
|---|---|
| SHA-256 | `c072653018239d92e9cd55e62813d712dec27ebb0a4bf17cf0398fc5d5a905cf` |
| Family label | `Mirai` |
| File name | `winki.arm6` |
| File type | `elf` |
| First seen | `2026-10-05 01:53:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `364d26917fc6d649c1caf7bb173a5848` |
| SHA-1 | `4ca86404462492edb02cf155c20fb5cff64fc91d` |
| SHA-256 | `c072653018239d92e9cd55e62813d712dec27ebb0a4bf17cf0398fc5d5a905cf` |
| SHA3-384 | `6d1f0572eab5d72c8a2c81f88f6239805d229f1a3b909b5645d9782a3a701ead4602e1c9c3394655f1aeb3c1eab2a4c7` |
| TLSH | `T18AD39349ED68A73DC3E372FEE75902CE333A1B9877E671219E314A953BC8B916435120` |
| SSDEEP | `3072:Z1hcuJ3i9qQiNn1bx3qVqyD7SD/v+Kd+GiF6jh0JdPM12:XvDDQF4AdPM12` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_c0726530
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c072653018239d92e9cd55e62813d712dec27ebb0a4bf17cf0398fc5d5a905cf"
    family = "Mirai"
    file_name = "winki.arm6"
    file_type = "elf"
    first_seen = "2026-10-05 01:53:23"
  condition:
    hash.sha256(0, filesize) == "c072653018239d92e9cd55e62813d712dec27ebb0a4bf17cf0398fc5d5a905cf"
}
```

### Sample 38: `eff3f4ab2ef40f7a`

| Field | Value |
|---|---|
| SHA-256 | `eff3f4ab2ef40f7ab1f1740ad7c22556a403a7c126c93799c419997be74b6575` |
| Family label | `Mirai` |
| File name | `winki.mips` |
| File type | `elf` |
| First seen | `2026-10-05 01:53:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7341a87f623d5ae0cbc0e70fa2ddc79e` |
| SHA-1 | `b89f842623b0cfeff8115010f9f1a77d281b33e4` |
| SHA-256 | `eff3f4ab2ef40f7ab1f1740ad7c22556a403a7c126c93799c419997be74b6575` |
| SHA3-384 | `03354592628c2a2aab186a40929d10f457fc3ffd721b95e42f8ba6eab5e33887ee4ba4c5f081888697b49c826723993c` |
| TLSH | `T141A3830F2E654F7DFB6E873847B79E329246239616D1C140D15CF9022F6424EB81FBAA` |
| TELFHASH | `t1db118818883c17f0ab925cac6fddff72e15050db0a125e338e00fdaada91a428e00c2c` |
| SSDEEP | `1536:FTHGGGWJhYVXn9AoR6U+krWE6UiHD/+DWAJFc5RN7Pk1DM91S6BBx7V3cmp:FHJhQ9IE6UiHmO1S6BBx71cmp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_eff3f4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff3f4ab2ef40f7ab1f1740ad7c22556a403a7c126c93799c419997be74b6575"
    family = "Mirai"
    file_name = "winki.mips"
    file_type = "elf"
    first_seen = "2026-10-05 01:53:21"
  condition:
    hash.sha256(0, filesize) == "eff3f4ab2ef40f7ab1f1740ad7c22556a403a7c126c93799c419997be74b6575"
}
```

### Sample 39: `cc4638f75f5d55ac`

| Field | Value |
|---|---|
| SHA-256 | `cc4638f75f5d55aca03e3d3d3b9c571c0899def48cb95887a2dbb11574e02e1a` |
| Family label | `Mirai` |
| File name | `winki.ppc` |
| File type | `elf` |
| First seen | `2026-10-05 01:53:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d51406f7713e296f873fd45bb0ef1d0` |
| SHA-1 | `82f3c52e21219fb6dd633a1a17babb21e57c1530` |
| SHA-256 | `cc4638f75f5d55aca03e3d3d3b9c571c0899def48cb95887a2dbb11574e02e1a` |
| SHA3-384 | `1c076d98718e083896a4a7baa4f4791d5f8948f8516c91e3b40c31ae22b5528e7ce554ce160a80f2504b7af37501d608` |
| TLSH | `T112630982622C0947C5E21EB0397B17E0D7AAEF9221F4F349260FB719D1B1D376846E9D` |
| SSDEEP | `1536:/CLhQHzmB3JLdvp3as2yJsJnv6V90gKigM:/CLh+zmVTv5JsJnv2K5M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_cc4638f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4638f75f5d55aca03e3d3d3b9c571c0899def48cb95887a2dbb11574e02e1a"
    family = "Mirai"
    file_name = "winki.ppc"
    file_type = "elf"
    first_seen = "2026-10-05 01:53:17"
  condition:
    hash.sha256(0, filesize) == "cc4638f75f5d55aca03e3d3d3b9c571c0899def48cb95887a2dbb11574e02e1a"
}
```

### Sample 40: `ead87b575e540b6f`

| Field | Value |
|---|---|
| SHA-256 | `ead87b575e540b6f5d5757d1c8bda695fe67be92b17e252106651d750e4744e6` |
| Family label | `Mirai` |
| File name | `winki.arm7` |
| File type | `elf` |
| First seen | `2026-10-05 01:48:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79084eeeddabc69c39ca17a670bcbde3` |
| SHA-1 | `25499c31435718b9acc8c385a88996d4d0182e99` |
| SHA-256 | `ead87b575e540b6f5d5757d1c8bda695fe67be92b17e252106651d750e4744e6` |
| SHA3-384 | `ab0812b45ab17289131adafb035140081bd569d51eba807586462edf772f85823a42e994e1568daf550b764e2e60ddde` |
| TLSH | `T186E3814CEE64AB3DC3E332FEE75902CE336A1B98B7E670219D314A5537C8B95A535120` |
| SSDEEP | `3072:+HvhA6gdpQPNfceNSi2qVqyD7MMGFRuwGf3n4goZcxBZPKXysYk3:RyNGMGFvaIgoZcxBdKb3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_ead87b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ead87b575e540b6f5d5757d1c8bda695fe67be92b17e252106651d750e4744e6"
    family = "Mirai"
    file_name = "winki.arm7"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:53"
  condition:
    hash.sha256(0, filesize) == "ead87b575e540b6f5d5757d1c8bda695fe67be92b17e252106651d750e4744e6"
}
```

### Sample 41: `5718c56f7378113d`

| Field | Value |
|---|---|
| SHA-256 | `5718c56f7378113dccb2e8aa3576a024f0f760127fd756fbfac239ee0c62c2a6` |
| Family label | `Mirai` |
| File name | `winki.arm` |
| File type | `elf` |
| First seen | `2026-10-05 01:48:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3e9c43289cc003764c029531818d427` |
| SHA-1 | `29ed4a22b779be05078e870a9e6dbdd1d6c1be37` |
| SHA-256 | `5718c56f7378113dccb2e8aa3576a024f0f760127fd756fbfac239ee0c62c2a6` |
| SHA3-384 | `d71d512232a7c2707ad9fcffe55e518b2898d503437e7ebd914f7d25de6ca74b75c2bbfc2a6f9532182a3c12a2123df2` |
| TLSH | `T1BF73188578869A1AC6D0537BFA0E43CD372573C8E2CE3203CD619F6176CA92F1DAB191` |
| TELFHASH | `t138b092e2560802c9a2c0428aa2d1a71a4970f127020b656186241b1dc846e83e54ed23` |
| SSDEEP | `768:w8XP/urX5fu5X8o27o3MoMPo+l5Zz70ba2cmGcwBJyxqLNIKmmIsqeknu1StVTXq:dXuZaGDFXUaxXlPywLWKggID/gP/p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_5718c56f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5718c56f7378113dccb2e8aa3576a024f0f760127fd756fbfac239ee0c62c2a6"
    family = "Mirai"
    file_name = "winki.arm"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:51"
  condition:
    hash.sha256(0, filesize) == "5718c56f7378113dccb2e8aa3576a024f0f760127fd756fbfac239ee0c62c2a6"
}
```

### Sample 42: `dc01fe12438a973d`

| Field | Value |
|---|---|
| SHA-256 | `dc01fe12438a973d7288c5fa2704df06d92df1c7b60f98e26a13186396b6b6d5` |
| Family label | `Mirai` |
| File name | `winki.mpsl` |
| File type | `elf` |
| First seen | `2026-10-05 01:48:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce30ed2acf633c3d591a840d3c7c8e0a` |
| SHA-1 | `6e7df49bb7ba2c280e2a00dcfa84db0e1dbb19fb` |
| SHA-256 | `dc01fe12438a973d7288c5fa2704df06d92df1c7b60f98e26a13186396b6b6d5` |
| SHA3-384 | `1b890af8922b7dd3992c33349e9253d137462f852c831d68467a03cfa407c7ef55d01e6ab59fc81f7100d1571ede6645` |
| TLSH | `T191A3710EBFA41EF7F86BCD3B05E81B0524CC651A21A93FB5B934D418FA5A10F15E38A5` |
| SSDEEP | `1536:xuhAg5M7Ghwk2V0WrLKyZzNUvI71j1zB5cZMqHZyT8uyD7:xql5QGhwkXWrLKyRNUiyjHmi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_dc01fe12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc01fe12438a973d7288c5fa2704df06d92df1c7b60f98e26a13186396b6b6d5"
    family = "Mirai"
    file_name = "winki.mpsl"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:48"
  condition:
    hash.sha256(0, filesize) == "dc01fe12438a973d7288c5fa2704df06d92df1c7b60f98e26a13186396b6b6d5"
}
```

### Sample 43: `361699bd9c276fdb`

| Field | Value |
|---|---|
| SHA-256 | `361699bd9c276fdbef11bc135de69dc2b2dc423c7460f96b5f42cf7eae2c2e83` |
| Family label | `Mirai` |
| File name | `winki.m68k` |
| File type | `elf` |
| First seen | `2026-10-05 01:48:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `757fc26bd0a7a88ff8d6aabce0227cce` |
| SHA-1 | `eaa7dab0e04b46538dc1b9d02e9b0d36b6be5258` |
| SHA-256 | `361699bd9c276fdbef11bc135de69dc2b2dc423c7460f96b5f42cf7eae2c2e83` |
| SHA3-384 | `c54f95b28db4814958217308f5f6121fe2e72b13cd169b8728005924fa844036f4d6c7069a10367e7109821fba26213b` |
| TLSH | `T13B633BD6E801AD3CFC4EE6BEC1554B09F931736899530A7B9162FCB32C321E45EA6E41` |
| SSDEEP | `1536:sfEU8x74k58y99F1bcRc3o8UiL5ERrX7WG:XckgR6fL8rrWG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_361699bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "361699bd9c276fdbef11bc135de69dc2b2dc423c7460f96b5f42cf7eae2c2e83"
    family = "Mirai"
    file_name = "winki.m68k"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:46"
  condition:
    hash.sha256(0, filesize) == "361699bd9c276fdbef11bc135de69dc2b2dc423c7460f96b5f42cf7eae2c2e83"
}
```

### Sample 44: `990fa84a88d86a9d`

| Field | Value |
|---|---|
| SHA-256 | `990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e` |
| Family label | `unknown` |
| File name | `990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e.exe` |
| File type | `exe` |
| First seen | `2026-10-05 01:48:45` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5aec7a7a816f79ec5e2d276ea99d60cd` |
| SHA-1 | `43a6f95c9b20329d49a719dc7335a0aa3416f1d9` |
| SHA-256 | `990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e` |
| SHA3-384 | `16fb0720ed1e790f46b9d29d7951edbcef1975c353d39b1bac54bcf71eebaa6b97bf4f0f169b073a61cade681db6eb56` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1A6E5D02B9642E6FEE01909353439D10009377E52A8480CDBDAF8F99CE7375753A2EB76` |
| SSDEEP | `49152:guI2hi1uPtffMIKHqTL9j07iun6HE4+Ymy+vvRbHR6a8CXcNoW9JZG/:g5OiWXrKHqTLO2xHGYmyo36NCXXW7C` |
| ICON-DHASH | `a2c496b686f0718e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_990fa84a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e"
    family = "unknown"
    file_name = "990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e.exe"
    file_type = "exe"
    first_seen = "2026-10-05 01:48:45"
  condition:
    hash.sha256(0, filesize) == "990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e"
}
```

### Sample 45: `e2546433e7d68641`

| Field | Value |
|---|---|
| SHA-256 | `e2546433e7d686414916ec02c249e99b2e57e10823c2ca8563e18ce46178a39b` |
| Family label | `Mirai` |
| File name | `winki.arm5` |
| File type | `elf` |
| First seen | `2026-10-05 01:48:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa67eae6c1952bc801ff3217e6d998e0` |
| SHA-1 | `73599e76362c838bf71b3e6b8186b966686d4998` |
| SHA-256 | `e2546433e7d686414916ec02c249e99b2e57e10823c2ca8563e18ce46178a39b` |
| SHA3-384 | `6511903d306b787b191e0facc2bfe84e8e707efaabb3cb5e5bcd4869b30a6f2995855afbea3db7bd5dbc319eeb1ed47e` |
| TLSH | `T1C073188578869A1AC6D0537BFA0E43CD372573C8E2CE3203CD619F6176CA92F1DAB191` |
| TELFHASH | `t138b092e2560802c9a2c0428aa2d1a71a4970f127020b656186241b1dc846e83e54ed23` |
| SSDEEP | `768:O8XP/urX5fu5X8o27o3MoMPo+l5Zz70ba2cmGcwBJyxqLNIKmmIsqeknu1StVTXq:zXuZaGDFXUaxXlPywLWKggID/gP/p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_e2546433
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2546433e7d686414916ec02c249e99b2e57e10823c2ca8563e18ce46178a39b"
    family = "Mirai"
    file_name = "winki.arm5"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:43"
  condition:
    hash.sha256(0, filesize) == "e2546433e7d686414916ec02c249e99b2e57e10823c2ca8563e18ce46178a39b"
}
```

### Sample 46: `f6bf1b51a3526dfe`

| Field | Value |
|---|---|
| SHA-256 | `f6bf1b51a3526dfe3178b81b6670491e745dc499987a100ac942de895ed84a21` |
| Family label | `Mirai` |
| File name | `winki.sh4` |
| File type | `elf` |
| First seen | `2026-10-05 01:48:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22c2e3a121978b753ffe87934127f92e` |
| SHA-1 | `4f55397f6308353a329100b56833d6e0da35196b` |
| SHA-256 | `f6bf1b51a3526dfe3178b81b6670491e745dc499987a100ac942de895ed84a21` |
| SHA3-384 | `0ad471bc6c866a5f446e139f0d3b649ab20a0f792f29ee391719f90beea515e64f59280eac7746c621a6ae51b5b2aa2c` |
| TLSH | `T1DE539E6AED3F3DC4E54905B8B824CF7C5723A909DAD759E188664272D007EDCBC983B8` |
| SSDEEP | `1536:QDp0xKDrf/rShdmbpNnlmD/1hL1hoekCN:Q1Drf/Tbp27Vhoek` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_f6bf1b51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6bf1b51a3526dfe3178b81b6670491e745dc499987a100ac942de895ed84a21"
    family = "Mirai"
    file_name = "winki.sh4"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:41"
  condition:
    hash.sha256(0, filesize) == "f6bf1b51a3526dfe3178b81b6670491e745dc499987a100ac942de895ed84a21"
}
```

### Sample 47: `42aa476e9677d875`

| Field | Value |
|---|---|
| SHA-256 | `42aa476e9677d875f15f6e09c8cdb40a461a2db58dadcb9b6c5adfd4a796d948` |
| Family label | `Mirai` |
| File name | `winki.x86` |
| File type | `elf` |
| First seen | `2026-10-05 01:48:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24442784e568ce34f714ee920ffc383b` |
| SHA-1 | `b09cbdac8f905c2e5a1504a2eb8fa9ae647d8028` |
| SHA-256 | `42aa476e9677d875f15f6e09c8cdb40a461a2db58dadcb9b6c5adfd4a796d948` |
| SHA3-384 | `926045c18236bbe66d33a73b788245a61d59a127f40e5a39e2c7603b44d05c3dbf23b0579f07b4415165445cfe272b6f` |
| TLSH | `T10B632803689081FCC551D1715B3FA53BD623F07E2135A68E77AA7F267E0EE211E1B18A` |
| TELFHASH | `t1e42159f5755609b121ff3137f30be5292c361ea518fa38d5d97261e2c7263c24ea2822` |
| SSDEEP | `1536:T2UgfuDqm6w+/FoVgUYpNS96dmPbGUjhCIN5p2:T2lfuro2qUYpY9CmPbDbN5p2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_42aa476e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42aa476e9677d875f15f6e09c8cdb40a461a2db58dadcb9b6c5adfd4a796d948"
    family = "Mirai"
    file_name = "winki.x86"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:39"
  condition:
    hash.sha256(0, filesize) == "42aa476e9677d875f15f6e09c8cdb40a461a2db58dadcb9b6c5adfd4a796d948"
}
```

### Sample 48: `f61318a710fa4fbd`

| Field | Value |
|---|---|
| SHA-256 | `f61318a710fa4fbd24b163df3a089bfcef25b04da61880e132064ec5c5d7ed5e` |
| Family label | `AgentTesla` |
| File name | `revised Invoice.js` |
| File type | `js` |
| First seen | `2026-10-05 01:32:52` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70afea5aa4689e70efb1428008a0a3ec` |
| SHA-1 | `cb6d417b8b06b426b2e258336c5f3f2c0fd019cb` |
| SHA-256 | `f61318a710fa4fbd24b163df3a089bfcef25b04da61880e132064ec5c5d7ed5e` |
| SHA3-384 | `d75fcf55be48ffc12760c8850b9c3c4dccc7c6065879ec24ecb7e905a182f61688cb0fadcd364a85c21a8d70045643ad` |
| TLSH | `T18CE4F16CD55B29A555AEC3082F4F8B5313E08B9F220ED1B8C059D7A1223B065F9F2DF9` |
| SSDEEP | `12288:aIxRUjousre7LFk5dlkKR4VewADh5OlEeB9I3JdjpsQ8XGZSTUD72vx0BpGRf43E:a8PSiyenhclEeB9I3JdjpslUDSx0BER5` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_048_f61318a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f61318a710fa4fbd24b163df3a089bfcef25b04da61880e132064ec5c5d7ed5e"
    family = "AgentTesla"
    file_name = "revised Invoice.js"
    file_type = "js"
    first_seen = "2026-10-05 01:32:52"
  condition:
    hash.sha256(0, filesize) == "f61318a710fa4fbd24b163df3a089bfcef25b04da61880e132064ec5c5d7ed5e"
}
```

### Sample 49: `2571f3fa3054da51`

| Field | Value |
|---|---|
| SHA-256 | `2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1` |
| Family label | `Mirai` |
| File name | `2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1` |
| File type | `elf` |
| First seen | `2026-10-05 01:17:16` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efde9155dd4d91ef09eb4825620745f2` |
| SHA-1 | `ca1550398f99d9169e8f2382fd338e8803cc6ad5` |
| SHA-256 | `2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1` |
| SHA3-384 | `70a575ffbc5685dcf2d680254a31d79d450b4c9ff6ca667eb60b0b0866abda60a9e348a61a378cb9ed344cee9769bbca` |
| TLSH | `T1E5543A8AFD81AE25D5C122BBFE2F428A331317B8D2EB71129D145F2476CA94F0F7A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_2571f3fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1"
    family = "Mirai"
    file_name = "2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1"
    file_type = "elf"
    first_seen = "2026-10-05 01:17:16"
  condition:
    hash.sha256(0, filesize) == "2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1"
}
```

### Sample 50: `b7689b12e1b94e62`

| Field | Value |
|---|---|
| SHA-256 | `b7689b12e1b94e628c8398ec86a6ad5ba564f107c5085464f3d03f408959545b` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-10-05 00:42:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46de0c763fbbfa3ef1da8d76ca7357fb` |
| SHA-1 | `cde1ff889d699ef852ea94052c69fcd20946df45` |
| SHA-256 | `b7689b12e1b94e628c8398ec86a6ad5ba564f107c5085464f3d03f408959545b` |
| SHA3-384 | `62722b135448bafa583ca18a08bad5326b6105971bd774d17da6c8190f603f18f6f6a72ecc26f028028922e8788dc637` |
| TLSH | `T198B20A84E547E0F1F41B46B880A6E73EDB30E52A6554D91BFF70977EEA13E11830B20A` |
| TELFHASH | `t1b2f0c2e1be7604f5fbcafd5ca71e2a03eb366da20b2164b980f623117ed3201c072015` |
| SSDEEP | `384:fCaiJsgpQn9ITTIDvqx2aeOkUYs883SlGlw0HyUhpeLza0pqq7ukzAU:CY9Iyvw2HwYsHvG0SUhpQa0pqqKOAU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_b7689b12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7689b12e1b94e628c8398ec86a6ad5ba564f107c5085464f3d03f408959545b"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-05 00:42:15"
  condition:
    hash.sha256(0, filesize) == "b7689b12e1b94e628c8398ec86a6ad5ba564f107c5085464f3d03f408959545b"
}
```

### Sample 51: `06f7f11cfc2c4018`

| Field | Value |
|---|---|
| SHA-256 | `06f7f11cfc2c401875f2f9aef30e2176ad3520d0d309c88361b2202ad67099a2` |
| Family label | `unknown` |
| File name | `temp.hta` |
| File type | `hta` |
| First seen | `2026-10-05 00:42:12` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f0bcf59bd10c28b439a7469c092e73f` |
| SHA-1 | `2ed9c4f3eeb0853c0b47808a054c0895ab9ea829` |
| SHA-256 | `06f7f11cfc2c401875f2f9aef30e2176ad3520d0d309c88361b2202ad67099a2` |
| SHA3-384 | `a25f816a85339d04140c1602b4ab7bca066509d13ef48261ee08260cdc9555ed63d1389bca8716a67c2c1a49def85635` |
| TLSH | `T12442185CAED1A2B0EA1707DEB7AF24690228A0C72009C484F94CDDE87F06BDD4A57B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzNbqFtCgSiRUM:sXX+/DV7k/3IFtPRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_06f7f11c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06f7f11cfc2c401875f2f9aef30e2176ad3520d0d309c88361b2202ad67099a2"
    family = "unknown"
    file_name = "temp.hta"
    file_type = "hta"
    first_seen = "2026-10-05 00:42:12"
  condition:
    hash.sha256(0, filesize) == "06f7f11cfc2c401875f2f9aef30e2176ad3520d0d309c88361b2202ad67099a2"
}
```

### Sample 52: `d07b4210db5c2610`

| Field | Value |
|---|---|
| SHA-256 | `d07b4210db5c2610daedc2831915af6c4e9f7966739ff789a0af2a18bb5dca66` |
| Family label | `Mirai` |
| File name | `kushnet.x64-test` |
| File type | `elf` |
| First seen | `2026-10-05 00:38:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1486e8975525823638df003964223af4` |
| SHA-1 | `fa670927e94469831ebbae86cc5fc89550eec70e` |
| SHA-256 | `d07b4210db5c2610daedc2831915af6c4e9f7966739ff789a0af2a18bb5dca66` |
| SHA3-384 | `24617e7e7c5eb92a0337f5aae89c8d44485785279f2c38a0b38bc019a47048784d18f91fbdff830a613770ade3685084` |
| TLSH | `T1FF256D2AB2B3B17CD007C03047DFCAA25531B4B526217D7F26C5DA353EA6DE12369B62` |
| TELFHASH | `t197d17b744afa39f0a6d7da11f362f1b19d7618e532d039e052276d84dfd0f801da281b` |
| SSDEEP | `12288:MueV7IM+3Ng0MWvO6qs1BHndHHvIHb69sF+Rq1/KxoXWaK6PGGH3s89eaycHqt5y:MueVUM+3NgqvVqsTy62F+SOodDH3s8F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_d07b4210
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d07b4210db5c2610daedc2831915af6c4e9f7966739ff789a0af2a18bb5dca66"
    family = "Mirai"
    file_name = "kushnet.x64-test"
    file_type = "elf"
    first_seen = "2026-10-05 00:38:02"
  condition:
    hash.sha256(0, filesize) == "d07b4210db5c2610daedc2831915af6c4e9f7966739ff789a0af2a18bb5dca66"
}
```

### Sample 53: `7850fe8380639928`

| Field | Value |
|---|---|
| SHA-256 | `7850fe83806399284d1b643547b6cdbfa3f1cc7413550514df0548b7eb1d3066` |
| Family label | `Mirai` |
| File name | `kushnet.arm6` |
| File type | `elf` |
| First seen | `2026-10-05 00:37:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f23cf0d3eae7bb4eb24652c187a419f0` |
| SHA-1 | `9513dd839abccd2ded082c2223464154225d937c` |
| SHA-256 | `7850fe83806399284d1b643547b6cdbfa3f1cc7413550514df0548b7eb1d3066` |
| SHA3-384 | `59fb1e152f5ff44a10037e4f721b7aa01d9d05c276e42a48182985fbb49977aaaf0129d0f623d7df7116be9149d4761a` |
| TLSH | `T17F04094AF9428E51F58012FAFB5D82D83F1303FBD2FA75029D185BB46B9745A0E2B942` |
| TELFHASH | `t118e0c225f9f817bdd3e844a60526c21a9e25389da705b816030c360aa84afc42028072` |
| SSDEEP | `3072:/wKE4gkmDpNewqm4ZLv8G6vyopDfiCxUn57BdbyqZRqYtB9MAUBdmIc8zf1Uqf:/ZETHNej1Lv8G6vyo1ajZtBGPk8zf1Uq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_7850fe83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7850fe83806399284d1b643547b6cdbfa3f1cc7413550514df0548b7eb1d3066"
    family = "Mirai"
    file_name = "kushnet.arm6"
    file_type = "elf"
    first_seen = "2026-10-05 00:37:59"
  condition:
    hash.sha256(0, filesize) == "7850fe83806399284d1b643547b6cdbfa3f1cc7413550514df0548b7eb1d3066"
}
```

### Sample 54: `cc16c460ded51ac5`

| Field | Value |
|---|---|
| SHA-256 | `cc16c460ded51ac533139917d16ef09eea894fd4058618c97d511de7722c460f` |
| Family label | `unknown` |
| File name | `macho_cc16c460ded5.bin` |
| File type | `macho` |
| First seen | `2026-10-05 00:34:24` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `104d50ebd1b3a42d1b2d41967e2414c2` |
| SHA-1 | `36c020c073eafeaf041ed11649576457911c5b7c` |
| SHA-256 | `cc16c460ded51ac533139917d16ef09eea894fd4058618c97d511de7722c460f` |
| SHA3-384 | `58ef57fbe943010b1439868feb1a3eb2fe37ddc29d66df4adae7cb980bfbad2d271ec78a93c1d2680f0b9aba8226365b` |
| TLSH | `T1DF55F200CF67549BF48CE7352E2B0A339E216194CA8561DE52622F88DE363E3F65F25D` |
| SSDEEP | `24576:1D15eJqwal17aKyG0hYPZsX4rtWZkB1Nno3Gz/3LameGE1YP5QHO9TmFGB5:1CqwXKyGKYBlz1Nn+VmeG+Yhtv5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_cc16c460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc16c460ded51ac533139917d16ef09eea894fd4058618c97d511de7722c460f"
    family = "unknown"
    file_name = "macho_cc16c460ded5.bin"
    file_type = "macho"
    first_seen = "2026-10-05 00:34:24"
  condition:
    hash.sha256(0, filesize) == "cc16c460ded51ac533139917d16ef09eea894fd4058618c97d511de7722c460f"
}
```

### Sample 55: `f5a7d9d169aff0ad`

| Field | Value |
|---|---|
| SHA-256 | `f5a7d9d169aff0adc6b109a35c5ad7f0f2fce8ce1d4425daaa405507181048ef` |
| Family label | `Mirai` |
| File name | `kushnet.mipsel` |
| File type | `elf` |
| First seen | `2026-10-05 00:33:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e422539150d1b9dfc35c075ca622588f` |
| SHA-1 | `b0585bf1a299c607933f2baa6d984b4cd0d90177` |
| SHA-256 | `f5a7d9d169aff0adc6b109a35c5ad7f0f2fce8ce1d4425daaa405507181048ef` |
| SHA3-384 | `82210cdfa3ee98a328f927aebe7b24cddbe6d62203b0dc6ddbc3c85127b4599051550f311d68ff7c29d7879897b20522` |
| TLSH | `T1F0543A03AE855ADBF41FCDB0897DC3C22EE1A0DB61E5A93A657C89DC7F5B10A05934C8` |
| SSDEEP | `6144:ZFDACUHS7/NGng21/hjFvZbiokno7x31Bz3u9Qz2813Oqq9:ZFxUHK4VjFH7p5z28RO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_f5a7d9d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5a7d9d169aff0adc6b109a35c5ad7f0f2fce8ce1d4425daaa405507181048ef"
    family = "Mirai"
    file_name = "kushnet.mipsel"
    file_type = "elf"
    first_seen = "2026-10-05 00:33:59"
  condition:
    hash.sha256(0, filesize) == "f5a7d9d169aff0adc6b109a35c5ad7f0f2fce8ce1d4425daaa405507181048ef"
}
```

### Sample 56: `889582f9f03be880`

| Field | Value |
|---|---|
| SHA-256 | `889582f9f03be880d3d9d2708561ad0241f8698df8537edbd0a5dc4fa8b42627` |
| Family label | `unknown` |
| File name | `macho_889582f9f03b.bin` |
| File type | `macho` |
| First seen | `2026-10-05 00:24:43` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34dd6cf4260b3b9c19d9eefba340efdb` |
| SHA-1 | `8c2a39c2300181d35547b68c3e9be6ed4c7ca433` |
| SHA-256 | `889582f9f03be880d3d9d2708561ad0241f8698df8537edbd0a5dc4fa8b42627` |
| SHA3-384 | `1016b67572b64778dd45248f793e6c37fdf28cd1879437adbad2c6a8b9c1effdd870f79fc6f194d672f356ac4f8db738` |
| TLSH | `T1432502018F614096FBDCC7301E768F378E766660898513DF6A862F989D31393F26726E` |
| SSDEEP | `24576:A8EBYSLszpU2dMIjdw4htdf8Nz5g2NMoFNGA/h:Ae22dMEzui2NM2J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_889582f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889582f9f03be880d3d9d2708561ad0241f8698df8537edbd0a5dc4fa8b42627"
    family = "unknown"
    file_name = "macho_889582f9f03b.bin"
    file_type = "macho"
    first_seen = "2026-10-05 00:24:43"
  condition:
    hash.sha256(0, filesize) == "889582f9f03be880d3d9d2708561ad0241f8698df8537edbd0a5dc4fa8b42627"
}
```

### Sample 57: `f380544dc352ff8d`

| Field | Value |
|---|---|
| SHA-256 | `f380544dc352ff8d00a9fa20722c12345241fd7c148b66cb8c0bb80f6917ccff` |
| Family label | `Mirai` |
| File name | `f380544dc352ff8d.bin` |
| File type | `elf` |
| First seen | `2026-10-05 00:24:13` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c5656c37ca809b06cc85c7369b447c7` |
| SHA-1 | `f72efbe6c4acf89cad480ecad24a963cf50032b7` |
| SHA-256 | `f380544dc352ff8d00a9fa20722c12345241fd7c148b66cb8c0bb80f6917ccff` |
| SHA3-384 | `eacde45fac7f7c46ba989e06b2a18d3dc83c455dc7cce0183940291bbfbfb47b353b0a67a2822fb2dbdd435e89f5558c` |
| TLSH | `T148A45C82FC929B12C6D02AB6FABE95CC331317F4D2EF70169D245F24678A45A0F77A05` |
| TELFHASH | `t17ec09b70089f03859310f685455fd954c67d713477c11cd59a0428861135f451e1691d` |
| SSDEEP | `12288:IjyDUQ4wP3bVCQjjg9mWSfNpYSW3drZ2vvVVatgxqPg99O5T7BgHyim7fI4:KE4wPP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_f380544d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f380544dc352ff8d00a9fa20722c12345241fd7c148b66cb8c0bb80f6917ccff"
    family = "Mirai"
    file_name = "f380544dc352ff8d.bin"
    file_type = "elf"
    first_seen = "2026-10-05 00:24:13"
  condition:
    hash.sha256(0, filesize) == "f380544dc352ff8d00a9fa20722c12345241fd7c148b66cb8c0bb80f6917ccff"
}
```

### Sample 58: `2721dbcd118b8c4f`

| Field | Value |
|---|---|
| SHA-256 | `2721dbcd118b8c4f018ff09a96c10bf5e60ee537a4ccc9c83ed824d90d49af14` |
| Family label | `Mirai` |
| File name | `2721dbcd118b8c4f.bin` |
| File type | `elf` |
| First seen | `2026-10-05 00:24:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84e596b93bd712bbe52869762f1aec4b` |
| SHA-1 | `c2b8ea6333a5557245179c1e942ce5dad46754a3` |
| SHA-256 | `2721dbcd118b8c4f018ff09a96c10bf5e60ee537a4ccc9c83ed824d90d49af14` |
| SHA3-384 | `18fdc56f2823cef8132e001c69ea7e21351068f41ec28a8986c4684a9da7bb1d4162b6cb0293861cbe05ac13734d644e` |
| TLSH | `T1ED533A17B94280FDC49AC1744A2BBA3ADD3770FD0378B2A677D4EB222CA6D215E19D44` |
| TELFHASH | `t17d210ea1b9241d64f0f7f511ab09e1000a310a6419ea79f2d0b1b5fade91bc20ab9c37` |
| SSDEEP | `1536:Y5S8iA+Ebh+uRjihp1pvyWwTUrSDpy6Y0CSU3f/CMx:WiFEbh+AGh7pvlwoQpy6Y010f/Cu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_2721dbcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2721dbcd118b8c4f018ff09a96c10bf5e60ee537a4ccc9c83ed824d90d49af14"
    family = "Mirai"
    file_name = "2721dbcd118b8c4f.bin"
    file_type = "elf"
    first_seen = "2026-10-05 00:24:04"
  condition:
    hash.sha256(0, filesize) == "2721dbcd118b8c4f018ff09a96c10bf5e60ee537a4ccc9c83ed824d90d49af14"
}
```

### Sample 59: `507611a45de2fa9f`

| Field | Value |
|---|---|
| SHA-256 | `507611a45de2fa9f20c1e26e4274b655faf7f47cb2688a1782da25604a2e34c6` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-05 00:21:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d5f8599070210e6d747ad73db609ccc` |
| SHA-1 | `2f9ffa93c8a7b99a72cda7e99a9dfbf97b7e9b43` |
| SHA-256 | `507611a45de2fa9f20c1e26e4274b655faf7f47cb2688a1782da25604a2e34c6` |
| SHA3-384 | `8bcdc879ff75f2f109450f29c015e00cba8100ed44c6d34d493f7abe6687a30c9760fc34bcb6b4ef018bde6ce7364492` |
| TLSH | `T1D1A45B82FC929B12C6D06AB6FABE91CC331317F4D2EF70169D245F24678A45A0F77A05` |
| TELFHASH | `t1b3c092b1a0977bd09670a70a43aab615cd9a11eb2e4299f552b9f9031142a408b21b2e` |
| SSDEEP | `12288:zumFN+2J4BsFLJI90MnbdkkW32+Ut3GSHCr+uaKD2sPe9mNYvUwSwSrVUg:6N2SXx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_507611a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "507611a45de2fa9f20c1e26e4274b655faf7f47cb2688a1782da25604a2e34c6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-05 00:21:54"
  condition:
    hash.sha256(0, filesize) == "507611a45de2fa9f20c1e26e4274b655faf7f47cb2688a1782da25604a2e34c6"
}
```

### Sample 60: `a1b9cf98985d4b1a`

| Field | Value |
|---|---|
| SHA-256 | `a1b9cf98985d4b1a3b571828bfec90ab03727a9c43f88adfe58d096dcb8ec568` |
| Family label | `Mirai` |
| File name | `kushnet.m68k` |
| File type | `elf` |
| First seen | `2026-10-05 00:17:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d11d12b0f00728af2807dd2b2f5eca28` |
| SHA-1 | `834fd683110eb53c6b0968d3614f7329f72a9dc6` |
| SHA-256 | `a1b9cf98985d4b1a3b571828bfec90ab03727a9c43f88adfe58d096dcb8ec568` |
| SHA3-384 | `269c94b9bdb596465acb156622b13ef40f3a11d2d4895b9650db4953f02d756516662df081bb1acf568bcdfd4b0c146d` |
| TLSH | `T12D047E03B0033F1DF0D21A3A426E5FA53FA891D76B720D969251A5E76BB32B02E5DC71` |
| SSDEEP | `3072:M7A/mGYNJ/5VpJjETWqxE8eSuD7n7iMHm08TS41pkQE:M7A/mZJ/5VpJ4fE8GRH38TS40` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_a1b9cf98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1b9cf98985d4b1a3b571828bfec90ab03727a9c43f88adfe58d096dcb8ec568"
    family = "Mirai"
    file_name = "kushnet.m68k"
    file_type = "elf"
    first_seen = "2026-10-05 00:17:58"
  condition:
    hash.sha256(0, filesize) == "a1b9cf98985d4b1a3b571828bfec90ab03727a9c43f88adfe58d096dcb8ec568"
}
```

### Sample 61: `b2caaa4db2b844ea`

| Field | Value |
|---|---|
| SHA-256 | `b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0` |
| Family label | `Mirai` |
| File name | `b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0` |
| File type | `elf` |
| First seen | `2026-10-05 00:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `115643ae0bf449b1883c0f4ac2e27366` |
| SHA-1 | `555a39c155edbdc3687f7975bacb3be639eedc60` |
| SHA-256 | `b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0` |
| SHA3-384 | `c09b5673a33e79c8d376d41bf84aecc8f6d9796728d03bfa3e37b67e6d9e79783345b43613b32b8a59e4759313492841` |
| TLSH | `T13BE3199FFC81AE6546C127BBFE2E418A331317B4D2EB71029D141F2876CA94F0E7A552` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabED:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_b2caaa4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0"
    family = "Mirai"
    file_name = "b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0"
    file_type = "elf"
    first_seen = "2026-10-05 00:17:14"
  condition:
    hash.sha256(0, filesize) == "b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0"
}
```

### Sample 62: `998bed38abfa7e80`

| Field | Value |
|---|---|
| SHA-256 | `998bed38abfa7e807bb2c8d0e0d54cb499c56f0583a99984ac24341b51c4d9e4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-05 00:15:25` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, s, soft` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb29804c69ccbdc40b7ce8887057e7f6` |
| SHA-1 | `f50141395e07d95ddbd2988a0971ee58b4e225f1` |
| SHA-256 | `998bed38abfa7e807bb2c8d0e0d54cb499c56f0583a99984ac24341b51c4d9e4` |
| SHA3-384 | `09567e366843014319697841c82411715dea3de1130f3490ae20e4f0b68c062dfedbb10126f7cb5039cb927e1f84ce96` |
| IMPHASH | `1802a55ddb2aa93e2a4096c636b74c52` |
| TLSH | `T16CC52707D3FA81D8E1FBE730CAB262731D72BC195538E55E1685DA251E30E709F29B22` |
| SSDEEP | `49152:tekPsdLwGm1Jd8ucriMAQFEt2SbKeRBdWN5uCT8:ta/wFMAQStjKeRBdWNw` |
| ICON-DHASH | `944a63b4125848c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_998bed38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998bed38abfa7e807bb2c8d0e0d54cb499c56f0583a99984ac24341b51c4d9e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-05 00:15:25"
  condition:
    hash.sha256(0, filesize) == "998bed38abfa7e807bb2c8d0e0d54cb499c56f0583a99984ac24341b51c4d9e4"
}
```

### Sample 63: `2f86a4fe00548a8a`

| Field | Value |
|---|---|
| SHA-256 | `2f86a4fe00548a8ac9cf5941bfcece12e8d1f815ce720bbd02a8fa7b93ef015c` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-05 00:06:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfb471d7c3a01f0f2f45794e7bfdab24` |
| SHA-1 | `68c89f23c4eb5bf7d89b9704ac6350bb6c71b6d2` |
| SHA-256 | `2f86a4fe00548a8ac9cf5941bfcece12e8d1f815ce720bbd02a8fa7b93ef015c` |
| SHA3-384 | `d5aa21f150032329985651a959825d6613cbd7d7d04cd84dbf1ef1ee6b0920ca41eb948bb111a94b83280f8b84cf9ddd` |
| TLSH | `T10CB24A95E6C3E0F3D89401FD11A3D7116772F8382176FD4BEB2016BBA802961A74BB9D` |
| TELFHASH | `t1f0f0f6e07d6600e4f2c5bd5c9b0f6613cf362da2072324ab4cf5f2013be16519171d05` |
| SSDEEP | `384:fO7o+KLO0HmRVvpnRR3I0zFg8q7/kRuJTco2XURhC1N9JmE3CkkRgSr:KNKLO0HmRVvpnD3fShJ6UvCvmE35kRH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_2f86a4fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f86a4fe00548a8ac9cf5941bfcece12e8d1f815ce720bbd02a8fa7b93ef015c"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-05 00:06:06"
  condition:
    hash.sha256(0, filesize) == "2f86a4fe00548a8ac9cf5941bfcece12e8d1f815ce720bbd02a8fa7b93ef015c"
}
```

### Sample 64: `b126a5682d497b3f`

| Field | Value |
|---|---|
| SHA-256 | `b126a5682d497b3f0c2c4d6c34c52091ed973e475ac7019f65f941d9690efe27` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-05 00:06:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c16ef3d885480b33a831395cb01bea9` |
| SHA-1 | `ea4b9836ea844e2d13af46fe0ee55c36d5060e8e` |
| SHA-256 | `b126a5682d497b3f0c2c4d6c34c52091ed973e475ac7019f65f941d9690efe27` |
| SHA3-384 | `4164c8dbf9088ed30cd243fd39104791738d4d21cd9163a54a5caece43e14ef926fa15e9475d64148a934302b1ba60a5` |
| TLSH | `T197B24C86FD814517CAE51176FA2E928D37665BB4E2FF3303AB261F642742A1F0F3A405` |
| TELFHASH | `t158115711864c8d9eb240856ce1ad46031626e1ba3c7e3a62bdfb981f810bcf39471926` |
| SSDEEP | `384:dG2m2FfIQp9Mgj6JwqQ87+2eZvaBcjQOF9hM4CXc5aceBy6jdmFx4eU:dfyRVg87+zvaOPFLMUqy6jF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_b126a568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b126a5682d497b3f0c2c4d6c34c52091ed973e475ac7019f65f941d9690efe27"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-05 00:06:04"
  condition:
    hash.sha256(0, filesize) == "b126a5682d497b3f0c2c4d6c34c52091ed973e475ac7019f65f941d9690efe27"
}
```

### Sample 65: `8a77b02b82e8759b`

| Field | Value |
|---|---|
| SHA-256 | `8a77b02b82e8759b6c502d656995603b249284eb9651d41f2c9517acaa65f6da` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-05 00:01:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee15a6a57a220207d77fdb4b2c00d8f6` |
| SHA-1 | `bc141c9b0ed05c11b44615df8adb8478bf6383cb` |
| SHA-256 | `8a77b02b82e8759b6c502d656995603b249284eb9651d41f2c9517acaa65f6da` |
| SHA3-384 | `c222eeb4323933be1eeda0ecd65a7ac4be4e4d0a86765ed48ee2d4ac28a5911aa1d553abac3c37c87e9ef1040d083915` |
| TLSH | `T15203094AF9818B12C5E115BAFA2E524D3313077CE3EF7226AE106A34679757B0B3A815` |
| TELFHASH | `t12bf0592002449de865fc4445de7ed4827041abb636bc380b7be3bd6d832b5a1b03009e` |
| SSDEEP | `768:ttnvcGn539x6CfbXjPnfnrhpgD5mkcIYGWi0HGBFDKAM:ttnfn53mCXnfnr4g3ImiuGr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_8a77b02b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a77b02b82e8759b6c502d656995603b249284eb9651d41f2c9517acaa65f6da"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-05 00:01:55"
  condition:
    hash.sha256(0, filesize) == "8a77b02b82e8759b6c502d656995603b249284eb9651d41f2c9517acaa65f6da"
}
```

### Sample 66: `a7997215ca6cfe70`

| Field | Value |
|---|---|
| SHA-256 | `a7997215ca6cfe70aa70cdb4225abc514e650307e6f6e2cf48a565d7b11a56af` |
| Family label | `Mirai` |
| File name | `kushnet.arm7` |
| File type | `elf` |
| First seen | `2026-10-05 00:01:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c52dae94478042eb3a3fddf13c50bf1` |
| SHA-1 | `2c4f6fca37906474bbe024d4d3682017a7e1f666` |
| SHA-256 | `a7997215ca6cfe70aa70cdb4225abc514e650307e6f6e2cf48a565d7b11a56af` |
| SHA3-384 | `2bfb774c9005f3258d280fbac916ebcf2397ca662588df865b251beaf2ad1cfff45338ba269be929518258fe86a7aa61` |
| TLSH | `T1ED041846F951CE51F58012F9BB4D83D83B1303FBC3FA74029C195BB86B97A5A0E3A942` |
| TELFHASH | `t1f0d05e29f57827b8f6dac390cd49483f89a279ce6f9824258d9027af2c42e95b018476` |
| SSDEEP | `3072:1AlB9PMR/viyca4txCUpDUHCFUe++ydb39LRo+WXQsBUJ6FDc8nQFUqd:SlB9PMlviyca4txCUXXkfWXhw58nQFUU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_a7997215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7997215ca6cfe70aa70cdb4225abc514e650307e6f6e2cf48a565d7b11a56af"
    family = "Mirai"
    file_name = "kushnet.arm7"
    file_type = "elf"
    first_seen = "2026-10-05 00:01:53"
  condition:
    hash.sha256(0, filesize) == "a7997215ca6cfe70aa70cdb4225abc514e650307e6f6e2cf48a565d7b11a56af"
}
```

### Sample 67: `5c48e2f8fa87d700`

| Field | Value |
|---|---|
| SHA-256 | `5c48e2f8fa87d70064e5a6aaf4d1d8fb78a76633f6b24927e3866b17d05bb9e0` |
| Family label | `unknown` |
| File name | `Captcha.hta` |
| File type | `hta` |
| First seen | `2026-10-04 23:49:49` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa5d00709dc5b99fe30e8959bab5b8c5` |
| SHA-1 | `f912bcaefa40ffeca3c4f40e1cd0ffb61f759940` |
| SHA-256 | `5c48e2f8fa87d70064e5a6aaf4d1d8fb78a76633f6b24927e3866b17d05bb9e0` |
| SHA3-384 | `0785888fca5aa698682766a940264897221d02f23f4401357b548f3328c19d8a4f37be02353bdc5cf9ce9d11bd70b788` |
| TLSH | `T11A321B9CAE90B1B0E21753CE37EF2429122491C3140AC684FE4C6EE9BF467CD6A97F55` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzM36cnsEJTYh1LdNOk/ev:sXX+/DV7k/3M37sEJTY/LHf/ev` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_5c48e2f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c48e2f8fa87d70064e5a6aaf4d1d8fb78a76633f6b24927e3866b17d05bb9e0"
    family = "unknown"
    file_name = "Captcha.hta"
    file_type = "hta"
    first_seen = "2026-10-04 23:49:49"
  condition:
    hash.sha256(0, filesize) == "5c48e2f8fa87d70064e5a6aaf4d1d8fb78a76633f6b24927e3866b17d05bb9e0"
}
```

### Sample 68: `2a82f1ad66901ddb`

| Field | Value |
|---|---|
| SHA-256 | `2a82f1ad66901ddb28bbf12e999bf44417576ed3ce0ed264275ec6f2c64f8313` |
| Family label | `Mirai` |
| File name | `kushnet.arm5` |
| File type | `elf` |
| First seen | `2026-10-04 23:49:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3f5aa0697c6ab74aa9b6c9508708178` |
| SHA-1 | `520dda66f630bb734630d2946aae2fdeeaf2db3f` |
| SHA-256 | `2a82f1ad66901ddb28bbf12e999bf44417576ed3ce0ed264275ec6f2c64f8313` |
| SHA3-384 | `e895e12436c9df73a7c5e77876766bfc86913f5b8e20b926f366b1bea4245b9601ec2d6ce5308a6366ea7923051ead53` |
| TLSH | `T19D14095AF8428E51F5D016F9FB8D82D83B1303FBD2FA34069D194BB467D789A0E3A542` |
| TELFHASH | `t111e0c26675e82b9ca7dac2f0de8d803849b1388c66652a138f48d38e888adc0300c472` |
| SSDEEP | `3072:NIenVvzNy3xm8qi1KYYee5pYPfP5NurWhv2treviwwo0Kwnnm5tXfXc8TA1Uq0:uqbYxm8qi1Hze5Y281iwwjnx8TA1Uq0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_2a82f1ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a82f1ad66901ddb28bbf12e999bf44417576ed3ce0ed264275ec6f2c64f8313"
    family = "Mirai"
    file_name = "kushnet.arm5"
    file_type = "elf"
    first_seen = "2026-10-04 23:49:47"
  condition:
    hash.sha256(0, filesize) == "2a82f1ad66901ddb28bbf12e999bf44417576ed3ce0ed264275ec6f2c64f8313"
}
```

### Sample 69: `6405edc4312d014d`

| Field | Value |
|---|---|
| SHA-256 | `6405edc4312d014d21abcc0ebadc11dfdf34a899ce679c63bc8337e85088cfe8` |
| Family label | `Mirai` |
| File name | `kushnet.x32` |
| File type | `elf` |
| First seen | `2026-10-04 23:49:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e58d40196a62820c3975a9b6e7aaa9f5` |
| SHA-1 | `e9d97d567e051959edc09874a2c3f39ff5ec57fa` |
| SHA-256 | `6405edc4312d014d21abcc0ebadc11dfdf34a899ce679c63bc8337e85088cfe8` |
| SHA3-384 | `d1a90186200b3a315fe5cdca2eede3dc6b80217fefa56add9dfcb44ea4f0fe8c9d2245d2f4dd9b1734d33564323bcf4a` |
| TLSH | `T1EE24390EF902D8B0F17290F1059EC3E17D7094F75237AD63EF6A2AF1BA272919E05259` |
| TELFHASH | `t1a0616bf61d6919e8b3d09d02d78e2b31fe2ad27b6860316505f31aa432ffd4251b9c78` |
| SSDEEP | `6144:gtTzwYIrbTzlgnzQCEsbYU83KIvkquSec:oNaT6nzQHsbYU83HkZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_6405edc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6405edc4312d014d21abcc0ebadc11dfdf34a899ce679c63bc8337e85088cfe8"
    family = "Mirai"
    file_name = "kushnet.x32"
    file_type = "elf"
    first_seen = "2026-10-04 23:49:45"
  condition:
    hash.sha256(0, filesize) == "6405edc4312d014d21abcc0ebadc11dfdf34a899ce679c63bc8337e85088cfe8"
}
```

### Sample 70: `467cef311f7c72e1`

| Field | Value |
|---|---|
| SHA-256 | `467cef311f7c72e1bbb8468c9c4dfe1cab9aa6dd6d93209f18f22c91441dd077` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-04 23:46:00` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, P, signed, UNIQPREM.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `941c767b1355c8b7d0e1dc91a28129fc` |
| SHA-1 | `228bc0ae5fa62756fa75ce1c1dcf0f32d913634c` |
| SHA-256 | `467cef311f7c72e1bbb8468c9c4dfe1cab9aa6dd6d93209f18f22c91441dd077` |
| SHA3-384 | `262f032d00d3a40d301e5d5130cada0f3b53abcc5afdbf898faa8ef9031c710296e70a5d7a1f915319d8cd13820ef534` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1D6E6F507724840D8C49BEB74C4B16A7622B07C9D97317B8B5FA96E642F267C47EBCB04` |
| SSDEEP | `49152:6/en8S0zynucqSbFwZTBdKlZUvnv5zjLJdzHhzGa94qg1WxJutbxLZsf4bqTs:X0uunRzpS6xJutbxLywbF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_467cef31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467cef311f7c72e1bbb8468c9c4dfe1cab9aa6dd6d93209f18f22c91441dd077"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 23:46:00"
  condition:
    hash.sha256(0, filesize) == "467cef311f7c72e1bbb8468c9c4dfe1cab9aa6dd6d93209f18f22c91441dd077"
}
```

### Sample 71: `24fabf58e8133d7d`

| Field | Value |
|---|---|
| SHA-256 | `24fabf58e8133d7d920622e7beacde41a0340d77e91529ab9822929ebecc4a3b` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-04 23:45:25` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b54257d238c1d25db93a04dca390072a` |
| SHA-1 | `67e8b0381c839e16b9faf419079b4d4823293592` |
| SHA-256 | `24fabf58e8133d7d920622e7beacde41a0340d77e91529ab9822929ebecc4a3b` |
| SHA3-384 | `a27a67b90c83a5d6950f51e12d5536175defe9929acd1547f864a5a622e0e2f733e71fa161a9481a626abd6a349e6497` |
| TLSH | `T1CBC20857A9C3B0FDC96982798296B038A273B0391239FD4637E5E72FAE7DE114E4D401` |
| TELFHASH | `t17cf054f077a63cf075eb7c776399d141c97c19f5002035e4d6609cf96e18f905c95812` |
| SSDEEP | `384:imwQCak2XDJj+TaASLMxrtb5mQSr+UXyL3jRM4ywnmlMB+:i70ljk6mns+TjRTkMB+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_24fabf58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24fabf58e8133d7d920622e7beacde41a0340d77e91529ab9822929ebecc4a3b"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-04 23:45:25"
  condition:
    hash.sha256(0, filesize) == "24fabf58e8133d7d920622e7beacde41a0340d77e91529ab9822929ebecc4a3b"
}
```

### Sample 72: `ce93d122add841b2`

| Field | Value |
|---|---|
| SHA-256 | `ce93d122add841b2d48c2554309d9572247e362a0f868d7d5e61e741bbce176f` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-04 23:45:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a8adaea5a286541c617f9aa1cd7474b` |
| SHA-1 | `6e6d5237dbcbc80694d9ef8a40217bd1ee13516c` |
| SHA-256 | `ce93d122add841b2d48c2554309d9572247e362a0f868d7d5e61e741bbce176f` |
| SHA3-384 | `c4586ead0700b44b6d868d0dc739c988ea603c3c58ab49c81f963f57aba02cf95c93e1bc826b61beb73620bc7a949111` |
| TLSH | `T1C3C2E7BDB513A9ACF44EFB3EC401410D7770A7255042163527EAA937DC733A81A7AE93` |
| SSDEEP | `384:ix1yTPRh1fP//tDFbwROmLB0FYkrOF8HAp3yxzehfa6oNl4Uv+9p:ix8TPRb6yFvrQ8E3yEda6kl4Uv+9p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_ce93d122
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce93d122add841b2d48c2554309d9572247e362a0f868d7d5e61e741bbce176f"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-04 23:45:22"
  condition:
    hash.sha256(0, filesize) == "ce93d122add841b2d48c2554309d9572247e362a0f868d7d5e61e741bbce176f"
}
```

### Sample 73: `2be178ca19dddfea`

| Field | Value |
|---|---|
| SHA-256 | `2be178ca19dddfeaf678fe36d2a01c11c3261811de079d6459ba4c9bcd916171` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-04 23:45:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ea888aee66c08755ddb67d0da2c654a` |
| SHA-1 | `180e88c9a61364c2160d4d84224aaf0a02b5bc31` |
| SHA-256 | `2be178ca19dddfeaf678fe36d2a01c11c3261811de079d6459ba4c9bcd916171` |
| SHA3-384 | `49e958b2d90847d381ba56c8020d01e9ef4fbcf7c9e802853958ba90ff3b19f3da4c6b403934b20e8612e927e5a22418` |
| TLSH | `T15623074AFD805F00D9E525BAFE1E524D33934B7CE3FE7111AE215B2523C6A2B0B7A911` |
| TELFHASH | `t18cf09e104a856cedf3d2190ad38e76439912aaea3f746c8633ebbc075337f82053029d` |
| SSDEEP | `1536:5lnESiKbuDyyyyyyyyoPoE/IOWNFXiK2lnkivAt+JHCmD:vikL/IOWNFA1At+Jik` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_2be178ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2be178ca19dddfeaf678fe36d2a01c11c3261811de079d6459ba4c9bcd916171"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-04 23:45:19"
  condition:
    hash.sha256(0, filesize) == "2be178ca19dddfeaf678fe36d2a01c11c3261811de079d6459ba4c9bcd916171"
}
```

### Sample 74: `9658a7f443c53943`

| Field | Value |
|---|---|
| SHA-256 | `9658a7f443c53943fea55027529a8fab90cd2ef118dddd37ab08544997e64abc` |
| Family label | `Mirai` |
| File name | `kushnet.mips` |
| File type | `elf` |
| First seen | `2026-10-04 23:40:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73b1f8429dc7303c860460102fcb6d41` |
| SHA-1 | `4190018e69e10fdb4530a1e67211f64ca2eb1ab0` |
| SHA-256 | `9658a7f443c53943fea55027529a8fab90cd2ef118dddd37ab08544997e64abc` |
| SHA3-384 | `cd3d970204016fb57f00193789118f927742f38ca363a438e7e0aaacd5b30a7595979a7844597634dd1732ba2b7cfc8e` |
| TLSH | `T10F541B2777228FA1F315C1310ABBCA967ED810D326F14895B32DCB5C3F2165A684BEE5` |
| TELFHASH | `t14e31b118493823f0a3715c9d5aedff3be56130db7a261c238e50e86dab6d9828e10c1c` |
| SSDEEP | `6144:ER0dC/SZsjCCrMGLxlNelhW5fKqGe8/8jR70FX:EyjXCgGLJelM3Gx8174X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_9658a7f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9658a7f443c53943fea55027529a8fab90cd2ef118dddd37ab08544997e64abc"
    family = "Mirai"
    file_name = "kushnet.mips"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:43"
  condition:
    hash.sha256(0, filesize) == "9658a7f443c53943fea55027529a8fab90cd2ef118dddd37ab08544997e64abc"
}
```

### Sample 75: `eedc958f4c7862ef`

| Field | Value |
|---|---|
| SHA-256 | `eedc958f4c7862ef03e6d15e70ff7ad4ac34c4733a8cb3c8ceebcb68836d7b67` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-04 23:40:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a058a0987a789460e1e27cfeaa9ddb30` |
| SHA-1 | `8e59b032ff0a2b0694ec0c03185538b2d43e312b` |
| SHA-256 | `eedc958f4c7862ef03e6d15e70ff7ad4ac34c4733a8cb3c8ceebcb68836d7b67` |
| SHA3-384 | `cfdc8f27b4d9ef5eef0abeb185f245e6605b08782edd6c77b8f5254b847c179338d2bdf51342c385970b0ce02cc25825` |
| TLSH | `T179B21A0237180E97D09FB9B43A2F1BE493EBFF5111E5D681260E9BCAC1B5E371181D89` |
| SSDEEP | `384:LJlV1VF9wCFd5o7R7cmg9w+5i3UrVrLrZUq7NogAlwqPTdAMd7FltLV3mtxj:Lbdw227cxDZVVUGfqPZAORlT3Ej` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_eedc958f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eedc958f4c7862ef03e6d15e70ff7ad4ac34c4733a8cb3c8ceebcb68836d7b67"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:41"
  condition:
    hash.sha256(0, filesize) == "eedc958f4c7862ef03e6d15e70ff7ad4ac34c4733a8cb3c8ceebcb68836d7b67"
}
```

### Sample 76: `3a0fcd09f8c03b59`

| Field | Value |
|---|---|
| SHA-256 | `3a0fcd09f8c03b59a951a7cbbac7c53b20185188575e694aeac09f995a143a42` |
| Family label | `Mirai` |
| File name | `kushnet.ppc440` |
| File type | `elf` |
| First seen | `2026-10-04 23:40:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54b5da868b27b0388a5d07f3484ae3d6` |
| SHA-1 | `ab0f819abab3c9881c2df6f011df5d2e63592b97` |
| SHA-256 | `3a0fcd09f8c03b59a951a7cbbac7c53b20185188575e694aeac09f995a143a42` |
| SHA3-384 | `5a2276e9b8f7da41a465478f36c751223d44b0b751ea03414ba77f0432da9c303c6f370af4b1682d6fb575456a97b903` |
| TLSH | `T141443B02F7050962F4420EB05A7F07E6FFA140C305B5E90E5A0F979A1B339BAD5D7BA9` |
| SSDEEP | `6144:6voAyi45eS05Muyq0iedabmxATsN8NUTt:6vI6jyf86Tt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_3a0fcd09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a0fcd09f8c03b59a951a7cbbac7c53b20185188575e694aeac09f995a143a42"
    family = "Mirai"
    file_name = "kushnet.ppc440"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:38"
  condition:
    hash.sha256(0, filesize) == "3a0fcd09f8c03b59a951a7cbbac7c53b20185188575e694aeac09f995a143a42"
}
```

### Sample 77: `17c9b7dd459078cf`

| Field | Value |
|---|---|
| SHA-256 | `17c9b7dd459078cf11edb629a2ff32dfc0313e4d60a779c40f0783fcddd20084` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-10-04 23:40:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99f961f005a23d8b74b55a62524b7c8a` |
| SHA-1 | `68137ecae5bc8e21668437fa1bded5642cfe8ef8` |
| SHA-256 | `17c9b7dd459078cf11edb629a2ff32dfc0313e4d60a779c40f0783fcddd20084` |
| SHA3-384 | `d9a628bf918206ead95907754bfad8355124094f0d2941bbcbac3afbfa929f84bea102448a0831b9167827e7aeaad920` |
| TLSH | `T190B26CE18F3A1F94E26443B4642187385B53E42AB74F0EBE162FA3618453D8DF1967F8` |
| SSDEEP | `384:KG1lMaIPgfe4QFlCgg+Xzf38FmfIfRXomEvGNXevVLZhdr75zoZ/ynTqBg7xpK:KG1KaIWe4QbCT+emfI5RV2LDoJuvzK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_17c9b7dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17c9b7dd459078cf11edb629a2ff32dfc0313e4d60a779c40f0783fcddd20084"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:36"
  condition:
    hash.sha256(0, filesize) == "17c9b7dd459078cf11edb629a2ff32dfc0313e4d60a779c40f0783fcddd20084"
}
```

### Sample 78: `0e38556099f10acb`

| Field | Value |
|---|---|
| SHA-256 | `0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604` |
| Family label | `ConnectWise` |
| File name | `0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604.msi` |
| File type | `msi` |
| First seen | `2026-10-04 23:33:47` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81137b21900193ef1fd2690e3b5e1882` |
| SHA-1 | `c0cf8c3ad783fdc75021c3683469679b08bb7382` |
| SHA-256 | `0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604` |
| SHA3-384 | `f2c787007c89bda6824cc1e22182c47e73623dbd21554e00ec8d80290489f4f72cabcb7399f528515c7e6743639b5b07` |
| TLSH | `T117D6221327EC4959E0B38B79FC7609A44A3A7D59EE1295EF22647D0D2931F818CA3337` |
| SSDEEP | `196608:VZs6Uruc9XbJZs6UpZs6UeZs6UmZs6UNZs6UsZs6U7:VnCtxbJnYn1nRn0nfng` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_078_0e385560
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604"
    family = "ConnectWise"
    file_name = "0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604.msi"
    file_type = "msi"
    first_seen = "2026-10-04 23:33:47"
  condition:
    hash.sha256(0, filesize) == "0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604"
}
```

### Sample 79: `f02c012b21fbd9aa`

| Field | Value |
|---|---|
| SHA-256 | `f02c012b21fbd9aa636afc247ff6677a6e635845bb36ab4d1e0f1b404af27fa1` |
| Family label | `unknown` |
| File name | `Real Executor.exe` |
| File type | `exe` |
| First seen | `2026-10-04 23:23:45` |
| Reporter | `AmadeyHunter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fd7690ad52a07ac52e6406bb52db5ba` |
| SHA-1 | `3a46d0c9383d961a5eef7a94aa7261fd582fe7f2` |
| SHA-256 | `f02c012b21fbd9aa636afc247ff6677a6e635845bb36ab4d1e0f1b404af27fa1` |
| SHA3-384 | `6f4fba3b3c1d535636348987267bb3d2bcf3fdc5bc7c27de6e064c4e63aa2421694dd5617c3f411b3435e06d8faa4783` |
| IMPHASH | `9eba512b03d8cac8a6c4424e25e9f06e` |
| TLSH | `T18148F01663E111AAD577D178C7AB6203EB72B40713308BDB329C43652F73AE45E7AB60` |
| SSDEEP | `1572864:1Pp36F/iKRz3o0EL9uXpXFxAI/MZqNrGZVOc4XIoC3MnluZQrZa:1PpIl3heuXpX/z/5NivOcC7hlTrk` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_f02c012b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f02c012b21fbd9aa636afc247ff6677a6e635845bb36ab4d1e0f1b404af27fa1"
    family = "unknown"
    file_name = "Real Executor.exe"
    file_type = "exe"
    first_seen = "2026-10-04 23:23:45"
  condition:
    hash.sha256(0, filesize) == "f02c012b21fbd9aa636afc247ff6677a6e635845bb36ab4d1e0f1b404af27fa1"
}
```

### Sample 80: `0336851d92948169`

| Field | Value |
|---|---|
| SHA-256 | `0336851d92948169ecd1e2499c21ab87299055af61e55fe1c1e1e7d83d3d1278` |
| Family label | `unknown` |
| File name | `Contact Information Regarding Cooperation Armaments and Military Attache Matters.html` |
| File type | `html` |
| First seen | `2026-10-04 23:22:01` |
| Reporter | `smica83` |
| Tags | `apt, html, WinterVivern` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27e5721e237cb0e795d7b206f9a1e99b` |
| SHA-1 | `569f6a49988e7a8927896a90568cd6c2c5051c47` |
| SHA-256 | `0336851d92948169ecd1e2499c21ab87299055af61e55fe1c1e1e7d83d3d1278` |
| SHA3-384 | `bf4c16450463f58a67fdfd877358d2d90e11336d29b00d700704bacc5050a9f1bce1473e216c2a316582fc0414b1b5ca` |
| TLSH | `T17DF2BF04BFFD3A5AA54105615DB06F833DEE5037C6CD4852BC5E62FE8FA4EE9010761A` |
| SSDEEP | `384:4kAeYD59OwdtozOrzFiJDCFb0M9wEvkHs1sKqyDAFXvlG4865So1hoojKP305s3T:oe6vtzFSC90MlMM1pJDAV9Ix0ooC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `html`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_0336851d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0336851d92948169ecd1e2499c21ab87299055af61e55fe1c1e1e7d83d3d1278"
    family = "unknown"
    file_name = "Contact Information Regarding Cooperation Armaments and Military Attache Matters.html"
    file_type = "html"
    first_seen = "2026-10-04 23:22:01"
  condition:
    hash.sha256(0, filesize) == "0336851d92948169ecd1e2499c21ab87299055af61e55fe1c1e1e7d83d3d1278"
}
```

### Sample 81: `cf68e31b765dca74`

| Field | Value |
|---|---|
| SHA-256 | `cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2` |
| Family label | `Mirai` |
| File name | `cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2` |
| File type | `elf` |
| First seen | `2026-10-04 23:17:15` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27efd00dff36dd470d1e726c94df24ee` |
| SHA-1 | `6b7fea3e6b822c4b02df955f6e86affe41887404` |
| SHA-256 | `cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2` |
| SHA3-384 | `53f6a6aeccdb296be86a4c37e0d8d82583575efaf200bfee437078c91d5c5a8e5eb4a8f732f1f00862ef1f5d324bea16` |
| TLSH | `T1DE34298AFC81AF65D5D422BBFE2E428A331317B8D2EA71129D145F2477CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqO/:T2s/bW+UmJqBxAuaPRhVabEDSDP99zB5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_cf68e31b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2"
    family = "Mirai"
    file_name = "cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2"
    file_type = "elf"
    first_seen = "2026-10-04 23:17:15"
  condition:
    hash.sha256(0, filesize) == "cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2"
}
```

### Sample 82: `c8e0831ac41f2723`

| Field | Value |
|---|---|
| SHA-256 | `c8e0831ac41f27233f76ee11b3b27284be0c055c1598f5aaa644aea46cdd95b8` |
| Family label | `unknown` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-04 23:00:39` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22bb58e7857a218259ade193bb74f502` |
| SHA-1 | `d6a21bd3b21dbc3b0edba6edda0467d719001cd5` |
| SHA-256 | `c8e0831ac41f27233f76ee11b3b27284be0c055c1598f5aaa644aea46cdd95b8` |
| SHA3-384 | `c1f4d488dc00a1301d98e3a0a39c897806de69be0c873ec28db52e804d64f9fc347f811a9487d6794ff08b95b85d96d1` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1F0C6B547338810DCC94BD6B144B0497912B23DEE4532BB4E4ED9BE942F1679A6FACF48` |
| SSDEEP | `49152:0Q3CDtwL+CP+OtNuYD+L63PkqLoJSY9RxBkBGHfyy7F5sGg:6w9ToJjpST` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_c8e0831a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8e0831ac41f27233f76ee11b3b27284be0c055c1598f5aaa644aea46cdd95b8"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-04 23:00:39"
  condition:
    hash.sha256(0, filesize) == "c8e0831ac41f27233f76ee11b3b27284be0c055c1598f5aaa644aea46cdd95b8"
}
```

### Sample 83: `7e54a36470395443`

| Field | Value |
|---|---|
| SHA-256 | `7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c` |
| Family label | `Mirai` |
| File name | `7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c` |
| File type | `elf` |
| First seen | `2026-10-04 22:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5fe746276a7ea8247d3005872357c28` |
| SHA-1 | `180dd6db14fc4a5d87cecf46c694965416eec20a` |
| SHA-256 | `7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c` |
| SHA3-384 | `eb4c2fc1089cc7144db77025aacaeb103ca7f1bffb817de177ad7173aa88778bb0f5a5f37c834109f0e6cf96c49bd58e` |
| TLSH | `T14DD3099FFD81AE6546C1277BFA2E418A331327B4D2DB71139D041F2876CA94F0E7A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmI:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZR9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_7e54a364
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c"
    family = "Mirai"
    file_name = "7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c"
    file_type = "elf"
    first_seen = "2026-10-04 22:17:14"
  condition:
    hash.sha256(0, filesize) == "7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c"
}
```

### Sample 84: `2e716444b93e04a5`

| Field | Value |
|---|---|
| SHA-256 | `2e716444b93e04a56e01fa485e7cbe32f5f601d1d183e112d29ea5cd83bad6f6` |
| Family label | `SilentNet` |
| File name | `Launcher.exe` |
| File type | `exe` |
| First seen | `2026-10-04 22:10:20` |
| Reporter | `rifteyy` |
| Tags | `exe, miner, silentnet, stealer, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c47b6133ffe78e1f31bbc77135e5a3d` |
| SHA-1 | `2318a0d5d558131807e6d1aa39fb6a416b1a2cfb` |
| SHA-256 | `2e716444b93e04a56e01fa485e7cbe32f5f601d1d183e112d29ea5cd83bad6f6` |
| SHA3-384 | `50ecd0a217159200c54f138c105449ede947a9e1317f7145b85c60561f3d1a84a742a7b726e7c68f2b10687e1839befe` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T106357C83E7A385D8C116C9B5534BF137F9627C8E4B157197ABC41E633A67BA4E22CB00` |
| SSDEEP | `12288:bbs/m0E54jwaFXGc8lEBBBHGBKq2IZwDgvfqItNqdg:bbOVE5ifGPRZwkvf3fd` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_084_2e716444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e716444b93e04a56e01fa485e7cbe32f5f601d1d183e112d29ea5cd83bad6f6"
    family = "SilentNet"
    file_name = "Launcher.exe"
    file_type = "exe"
    first_seen = "2026-10-04 22:10:20"
  condition:
    hash.sha256(0, filesize) == "2e716444b93e04a56e01fa485e7cbe32f5f601d1d183e112d29ea5cd83bad6f6"
}
```

### Sample 85: `9a1c175c7d56808a`

| Field | Value |
|---|---|
| SHA-256 | `9a1c175c7d56808a694be3939e0cf98d8097efd8f46f8fd317aa226171b5c9cd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-04 21:53:00` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f7e092f6bfadc775f55824c4b8b6d14` |
| SHA-1 | `610159edd188c795080c4122e4bb99a67aa0bc25` |
| SHA-256 | `9a1c175c7d56808a694be3939e0cf98d8097efd8f46f8fd317aa226171b5c9cd` |
| SHA3-384 | `2cb23b246bc0d248ed480418e82fe6ae1a96933c9a96aac3d0ad080f8b62cc1c09ce86e44e2133e3e228f3bc98293dfa` |
| IMPHASH | `d9d2a68d3c695010fd69ee8bbb785747` |
| TLSH | `T1E8B6BE5AA2E401E9D476C07CCAB78903F3B278521731A7EB15A146376F33BE15E3E660` |
| SSDEEP | `196608:Q0QX1Qb7BXeieDvl1EqXjEAHVEV1p7/K4RI7EQJdQZYNb8Y9TM:Q0QX1Qb7BXOl1NXjEAHVEV1p7A5Cy9Q` |
| ICON-DHASH | `134d4d4d4d4d4d13` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_9a1c175c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a1c175c7d56808a694be3939e0cf98d8097efd8f46f8fd317aa226171b5c9cd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 21:53:00"
  condition:
    hash.sha256(0, filesize) == "9a1c175c7d56808a694be3939e0cf98d8097efd8f46f8fd317aa226171b5c9cd"
}
```

### Sample 86: `d9d6f4d04fb0f2e2`

| Field | Value |
|---|---|
| SHA-256 | `d9d6f4d04fb0f2e2d16bf729035b2eb3dc7d7a160eddf9b43b6d5c794e77e4d1` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-04 21:40:52` |
| Reporter | `Bitsight` |
| Tags | `579cd0, dropped-by-Amadey, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3988eb28220b4dd05fb984aef5c08e4` |
| SHA-1 | `e919afe60d3520ba22d72bbb176186c79afb2788` |
| SHA-256 | `d9d6f4d04fb0f2e2d16bf729035b2eb3dc7d7a160eddf9b43b6d5c794e77e4d1` |
| SHA3-384 | `3e29d4ab1b35ab950f4d9029165c69654cf7af0ccc0d545bab722a72c88a4b8d272a9ec22eb5c2323ba424e6afc66c0a` |
| IMPHASH | `745ca2fef3bd4901aa31a10dc99358d2` |
| TLSH | `T12D55D037E89A8168DE7DF0B27828F640D78C7B058F93717D269E24837897C976862317` |
| SSDEEP | `24576:/Z1lzvjGufI7h59TlgzZ0aEypQzFvT5zJ3lvHsIQjb7lxJ3+LLIrup3v/J:/luSIxTmzqMpQlX3lvMIa7PUx3` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_086_d9d6f4d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d6f4d04fb0f2e2d16bf729035b2eb3dc7d7a160eddf9b43b6d5c794e77e4d1"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 21:40:52"
  condition:
    hash.sha256(0, filesize) == "d9d6f4d04fb0f2e2d16bf729035b2eb3dc7d7a160eddf9b43b6d5c794e77e4d1"
}
```

### Sample 87: `8b1b1714d9544d86`

| Field | Value |
|---|---|
| SHA-256 | `8b1b1714d9544d86284accdd3240df5ef641cf5504f4c8baebec5387e966524f` |
| Family label | `unknown` |
| File name | `Setup_winletlatst安装.exe` |
| File type | `exe` |
| First seen | `2026-10-04 21:31:42` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfa02c10692133124a81c074f5355773` |
| SHA-1 | `c673e15e27dc1e880b46ec9b3a2df22df9ec2656` |
| SHA-256 | `8b1b1714d9544d86284accdd3240df5ef641cf5504f4c8baebec5387e966524f` |
| SHA3-384 | `bb9db2309b17d07395f8508dfcc278b80324cea28f86ef4e5767eabc7bda7a0f9ee6af1aa0cbae0fd68d8215c961c194` |
| IMPHASH | `889da90ddbfdb9f6dce5db502d21d90a` |
| TLSH | `T16B6733ECF5C342B8C295083461F8B23B7B294A3BC631EE52D96ACD38BC535565C386A5` |
| SSDEEP | `786432:rjBnI0dIHPD8YUFjCrR4fWRZ9lm4RFFpP8:JBuYYRrefWr99RFDP8` |
| ICON-DHASH | `78e4d2d2d2c478b8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_8b1b1714
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b1b1714d9544d86284accdd3240df5ef641cf5504f4c8baebec5387e966524f"
    family = "unknown"
    file_name = "Setup_winletlatst安装.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:31:42"
  condition:
    hash.sha256(0, filesize) == "8b1b1714d9544d86284accdd3240df5ef641cf5504f4c8baebec5387e966524f"
}
```

### Sample 88: `25a546a305fbfe3b`

| Field | Value |
|---|---|
| SHA-256 | `25a546a305fbfe3b05f90139fe3f007818e5668192c6b74a9ea861b496de6566` |
| Family label | `unknown` |
| File name | `quickq.exe` |
| File type | `exe` |
| First seen | `2026-10-04 21:30:50` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47bcb4616f1967aaeb3ce2980aecd567` |
| SHA-1 | `90b7e21574da88009c651079f0929f116ae34260` |
| SHA-256 | `25a546a305fbfe3b05f90139fe3f007818e5668192c6b74a9ea861b496de6566` |
| SHA3-384 | `b35a664b5844933cfb71e14a1fe09a2a0e0f61bfae9be70d8f3fa7f7853b3e25281a00fe35526d5d407ac3dbef72ffa9` |
| IMPHASH | `efd455830ba918de67076b7c65d86586` |
| TLSH | `T1BF383326E586D03EE27B96350A3AEB2574372EB14A164C3767E47A5CCE311CD0F3E648` |
| SSDEEP | `3145728:KS0FWhtpQPZQPcR+t/7sEiKio6CIKnOYGl:KS0FIiQksF77iKfEK9Gl` |
| ICON-DHASH | `f0c896b28a9ec8f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_25a546a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25a546a305fbfe3b05f90139fe3f007818e5668192c6b74a9ea861b496de6566"
    family = "unknown"
    file_name = "quickq.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:30:50"
  condition:
    hash.sha256(0, filesize) == "25a546a305fbfe3b05f90139fe3f007818e5668192c6b74a9ea861b496de6566"
}
```

### Sample 89: `f31ece43389d70c6`

| Field | Value |
|---|---|
| SHA-256 | `f31ece43389d70c6351fa607e08e31a1e11f5d9d77968f4b515c833a1628973a` |
| Family label | `Gh0stRAT` |
| File name | `lightxtreme.exe` |
| File type | `exe` |
| First seen | `2026-10-04 21:29:35` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0stRAT, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbaf29a9c995b983bc0cf6d65f9397fa` |
| SHA-1 | `1adb2e8321dec6d9fc803bb406d0ae10e3ed501e` |
| SHA-256 | `f31ece43389d70c6351fa607e08e31a1e11f5d9d77968f4b515c833a1628973a` |
| SHA3-384 | `04b9c096869eb17dabbc62937a16215e56d2b1a660dcec0ff33633d54a616e38a39d76f6a8756fa18f8f0eee14dadb49` |
| IMPHASH | `efd455830ba918de67076b7c65d86586` |
| TLSH | `T19AF73316798B253FF07A893A4956A36155377F11A913886783F8386CCF3A6E04D3F70A` |
| SSDEEP | `1572864:QEKNJYkyHIv5TY3eMiBTHUL8sxbpu+cwoieKpZjbHpTFRG2wja:QFZaIv6ulUIwbY+HpZbN2a` |
| ICON-DHASH | `d00a2c1c074b2cf4` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_089_f31ece43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f31ece43389d70c6351fa607e08e31a1e11f5d9d77968f4b515c833a1628973a"
    family = "Gh0stRAT"
    file_name = "lightxtreme.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:29:35"
  condition:
    hash.sha256(0, filesize) == "f31ece43389d70c6351fa607e08e31a1e11f5d9d77968f4b515c833a1628973a"
}
```

### Sample 90: `ba5088e6fff5b63a`

| Field | Value |
|---|---|
| SHA-256 | `ba5088e6fff5b63a2316fc273029bb651436be91618ba53425e24e23c798ab2a` |
| Family label | `Gh0stRAT` |
| File name | `goujijiasuqi.exe` |
| File type | `exe` |
| First seen | `2026-10-04 21:28:44` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0stRAT, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b3f43a7fc536b20c354ba62f7626cd5` |
| SHA-1 | `f48114b06c9cdce08a19f7ec227c8bac82ae3100` |
| SHA-256 | `ba5088e6fff5b63a2316fc273029bb651436be91618ba53425e24e23c798ab2a` |
| SHA3-384 | `4653919d30bfce81e721fda21db110499229614c5a72937fa0b7679844ed1c463a64cf0d0e85f88f877933acdc9297d5` |
| IMPHASH | `efd455830ba918de67076b7c65d86586` |
| TLSH | `T1B9272222E98652AED0D585770531B021CB275FB0641AB8E6EEBEF47CCAF509C1D3E607` |
| SSDEEP | `393216:Wbtu9n1XuPMt57buL2XoaU8w5A2VKMx3IzbNFQhtO3yvDVgdrS+c:F9nVNuL2X5mKSI3N6f0yvhc9c` |
| ICON-DHASH | `6cdc9cac8c8680f8` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_090_ba5088e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba5088e6fff5b63a2316fc273029bb651436be91618ba53425e24e23c798ab2a"
    family = "Gh0stRAT"
    file_name = "goujijiasuqi.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:28:44"
  condition:
    hash.sha256(0, filesize) == "ba5088e6fff5b63a2316fc273029bb651436be91618ba53425e24e23c798ab2a"
}
```

### Sample 91: `01dec44e70c5c84d`

| Field | Value |
|---|---|
| SHA-256 | `01dec44e70c5c84d2e790a3f2bd4e8613ba82ebd1d13bfb9e4df20ea476ca559` |
| Family label | `Gh0stRAT` |
| File name | `flclash.exe` |
| File type | `exe` |
| First seen | `2026-10-04 21:28:02` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0stRAT, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11675510d8b56c9b11dadbb6e2b08d26` |
| SHA-1 | `ebb16e25f8fbe2d645a05173ecea323fe612c4b2` |
| SHA-256 | `01dec44e70c5c84d2e790a3f2bd4e8613ba82ebd1d13bfb9e4df20ea476ca559` |
| SHA3-384 | `40469952f6cd4dc1bc13af94ffc4c19329c567cc6eee44e971ed7ee15c4a0c0628b9176e0e420386f38df1c671f55967` |
| IMPHASH | `efd455830ba918de67076b7c65d86586` |
| TLSH | `T15F973322E98616AED1D584734536B121CB375FB1711A78EBEEBEF438CAF108D1D39602` |
| SSDEEP | `786432:O/co0MBOiY8o5t5zkbroyjx2ibYvH7DxElGFtxBx7Ynp2Iq9FCWteoTlBXkcvhce:O/Y0OiY84tqbromAiQHnXnt7Spfq9sOh` |
| ICON-DHASH | `6cdc9cac8c8680f8` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_091_01dec44e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01dec44e70c5c84d2e790a3f2bd4e8613ba82ebd1d13bfb9e4df20ea476ca559"
    family = "Gh0stRAT"
    file_name = "flclash.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:28:02"
  condition:
    hash.sha256(0, filesize) == "01dec44e70c5c84d2e790a3f2bd4e8613ba82ebd1d13bfb9e4df20ea476ca559"
}
```

### Sample 92: `73fa3523e75f8792`

| Field | Value |
|---|---|
| SHA-256 | `73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae` |
| Family label | `Mirai` |
| File name | `73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae` |
| File type | `elf` |
| First seen | `2026-10-04 21:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34d68e341c1e3c2f051649c21d562ee0` |
| SHA-1 | `11c61c5929b08a1de6ac739c56251105caaa81ad` |
| SHA-256 | `73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae` |
| SHA3-384 | `a182bb1bdafc6a00267a827c34e1f880aabc52e9c1d1f57b34eeefc42ce784beb418946c61d9dcbb106dd555930ff1a4` |
| TLSH | `T1F2F3189FFD81AE6546C527BBFE2E418A331317B4D2EA71029D141F2877CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSDPJ:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_73fa3523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae"
    family = "Mirai"
    file_name = "73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae"
    file_type = "elf"
    first_seen = "2026-10-04 21:17:14"
  condition:
    hash.sha256(0, filesize) == "73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae"
}
```

### Sample 93: `a62ae903603179c7`

| Field | Value |
|---|---|
| SHA-256 | `a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82` |
| Family label | `Mirai` |
| File name | `a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82` |
| File type | `elf` |
| First seen | `2026-10-04 20:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a5ba9e187246d288050ccd3cd0ea3cf` |
| SHA-1 | `1c8d9f3f68ff16b812f16832a21f4465a1fb7cdd` |
| SHA-256 | `a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82` |
| SHA3-384 | `65346889d4eec42cf7d3d246b4ed5e7931b4279dcdb9a33de446d13db26fe22bec22450de8215c505bcfe5de7fb8667c` |
| TLSH | `T18583089ABC919A9555D413BBBE7E818E331323B8D2DF7103CD045F18B6CA94F0E7A582` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DhrPDysX+4if3LEVwjUt87HwJXZ:T2s/ITo7WCkybotgsJ913DhrbW4UYSx4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_a62ae903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82"
    family = "Mirai"
    file_name = "a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82"
    file_type = "elf"
    first_seen = "2026-10-04 20:17:14"
  condition:
    hash.sha256(0, filesize) == "a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82"
}
```

### Sample 94: `c34ebc389e99c4bf`

| Field | Value |
|---|---|
| SHA-256 | `c34ebc389e99c4bfbddf726fc6f357aa625efb8afdf2abceef9454ab4026d687` |
| Family label | `unknown` |
| File name | `7c1cc22a11e0d0a49ce86d1e5a2943922555860450d7ad6559ca7bc7c4eec99c.zip` |
| File type | `zip` |
| First seen | `2026-10-04 20:12:42` |
| Reporter | `Kejult` |
| Tags | `Remus, RemusStealer, Stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a586376b3ba1ead4c801ec189c708a1` |
| SHA-1 | `899a61c8b123be664e3e18cf18c11316fe589396` |
| SHA-256 | `c34ebc389e99c4bfbddf726fc6f357aa625efb8afdf2abceef9454ab4026d687` |
| SHA3-384 | `d632913ece228df9d032cd9237094f9ea088abee76d6acf62a245fb44950961530aafe583f4af5572191d1151e586b44` |
| TLSH | `T16F068229978BE5B6C59D4130225F4BAF7AB181CE06A18306D3269C7E2CC3FD47F61E16` |
| SSDEEP | `49152:Yht/IWHdScQJO/CW7hwph+3/16XDOfkanLUq8QkhyYmyHfnktxMCejTgh:Yh3HwjU65h+FDgq8myHfktxz6TE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_c34ebc38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34ebc389e99c4bfbddf726fc6f357aa625efb8afdf2abceef9454ab4026d687"
    family = "unknown"
    file_name = "7c1cc22a11e0d0a49ce86d1e5a2943922555860450d7ad6559ca7bc7c4eec99c.zip"
    file_type = "zip"
    first_seen = "2026-10-04 20:12:42"
  condition:
    hash.sha256(0, filesize) == "c34ebc389e99c4bfbddf726fc6f357aa625efb8afdf2abceef9454ab4026d687"
}
```

### Sample 95: `92365a186dec592d`

| Field | Value |
|---|---|
| SHA-256 | `92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b` |
| Family label | `unknown` |
| File name | `92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b.exe` |
| File type | `exe` |
| First seen | `2026-10-04 20:01:57` |
| Reporter | `Kejult` |
| Tags | `exe, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee1e1675468944fd276af9a66e7e28a1` |
| SHA-1 | `2495314576a779acd4f0d35eb799c469f029f6a5` |
| SHA-256 | `92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b` |
| SHA3-384 | `2d4394252ecc81bc357d5622ac4daead93ca9a229379067f859dec15aa95e2eeb8bd5b669e60bcefa6c820d14e32fbcc` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T16C380103738800CCC95BDA7144B05A7962B13CED55327B9E8EA97F942F2A7946FADF04` |
| SSDEEP | `1572864:CCvuwBaGNg/XJH/Pw3r51TtzbcDbpzxEHH7lm5h+J7F9YYylGgUwg:xQGy/Xl/Pu5BtozxS7lmLiwY0lU9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_92365a18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b"
    family = "unknown"
    file_name = "92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b.exe"
    file_type = "exe"
    first_seen = "2026-10-04 20:01:57"
  condition:
    hash.sha256(0, filesize) == "92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b"
}
```

### Sample 96: `0b667fe4fc990f75`

| Field | Value |
|---|---|
| SHA-256 | `0b667fe4fc990f75d0ff341a3a8c0a6a8939006cbf74d1250e536dcaa020e262` |
| Family label | `Mirai` |
| File name | `morte.i686` |
| File type | `elf` |
| First seen | `2026-10-04 20:00:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `929ed65c13b919f15a7018bf19cfd953` |
| SHA-1 | `e399ed26884760ea72bdca4b22c45b76022daaa2` |
| SHA-256 | `0b667fe4fc990f75d0ff341a3a8c0a6a8939006cbf74d1250e536dcaa020e262` |
| SHA3-384 | `462cf04d9c178cc466583d1930bf9ad9e0ff31daccdea18f6d745736cde897b1eddf73836f929224c9de87a4c1a41a8f` |
| TLSH | `T14B7349C2B54B80F5E81B48B44127B33FCB32EA398066D65EDF6ADE35DA23441522739D` |
| TELFHASH | `t100310cf71abd4de8e7c09800c35e6f91196de73b156077a24532986822afed2507ac3d` |
| SSDEEP | `1536:w1qgsKS3397t7q3Ex92cQpIdBfhTWTQHWrmNbiYU22GHObdrxZ:wJA3Rte3Ex92ccIokHWrqbnU1H` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_0b667fe4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b667fe4fc990f75d0ff341a3a8c0a6a8939006cbf74d1250e536dcaa020e262"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-10-04 20:00:27"
  condition:
    hash.sha256(0, filesize) == "0b667fe4fc990f75d0ff341a3a8c0a6a8939006cbf74d1250e536dcaa020e262"
}
```

### Sample 97: `26774e49d90c14c8`

| Field | Value |
|---|---|
| SHA-256 | `26774e49d90c14c84cf1a99a466f22e474db036d97b05e9cdef94d7bfe49cfc0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-04 19:54:30` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3741db40b67f73ee4799e5f84cdbc785` |
| SHA-1 | `c2752c07e292f394e33280c3c0ded844e57741b7` |
| SHA-256 | `26774e49d90c14c84cf1a99a466f22e474db036d97b05e9cdef94d7bfe49cfc0` |
| SHA3-384 | `70f8d526adbd8cb902b27bc671f9b2468fa47cad0d052b0ea47ebf1a3f4edffa457a0ba84a4180d8bdbd01366bc978e6` |
| IMPHASH | `694a10f92efdb5ba9c32ad08fff67a41` |
| TLSH | `T174E43A66DA527990ED53803DC91A6307AB7E3F814414F97122299EC1376CDAB389FB0F` |
| SSDEEP | `6144:GbDcLTAtfpGEFeZCdcPfaelc3VKeCpyX727bxdv1Vw0xRaurzCZ:GbWTAX5FevHaWGCpi2hLy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_26774e49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26774e49d90c14c84cf1a99a466f22e474db036d97b05e9cdef94d7bfe49cfc0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 19:54:30"
  condition:
    hash.sha256(0, filesize) == "26774e49d90c14c84cf1a99a466f22e474db036d97b05e9cdef94d7bfe49cfc0"
}
```

### Sample 98: `4cd800261d0e873e`

| Field | Value |
|---|---|
| SHA-256 | `4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11` |
| Family label | `Mirai` |
| File name | `4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11` |
| File type | `elf` |
| First seen | `2026-10-04 19:51:58` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f606795181195b17af4e17b506c951ae` |
| SHA-1 | `883a1270bc57b5eba0feee5e64a80035d64c1e49` |
| SHA-256 | `4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11` |
| SHA3-384 | `5ee8b66c790eb28e275b96029613b863c37b39695a26497d1ee6a0c782c60801560e0b1b3f2de6b2ea79cfa3440acbe2` |
| TLSH | `T164834A03B5C088FDC88AC1346B6FA536D833F07D2275B25B67D4FE22AD9DD506E2A605` |
| TELFHASH | `t15d317d713d9a197060fbf232b346d2e159342e6020f431c5d5b2a8face673964e71837` |
| SSDEEP | `1536:ZR8lAGTE8CEPre7vyUaD5W7Qx1fe+6M1RT5yldmqkk/M:4lbTE6Pijy5Ws1fe+1RT5ylYrr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_4cd80026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11"
    family = "Mirai"
    file_name = "4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11"
    file_type = "elf"
    first_seen = "2026-10-04 19:51:58"
  condition:
    hash.sha256(0, filesize) == "4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11"
}
```

### Sample 99: `f74135143232bc1a`

| Field | Value |
|---|---|
| SHA-256 | `f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2` |
| Family label | `Mirai` |
| File name | `f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2` |
| File type | `sh` |
| First seen | `2026-10-04 19:51:50` |
| Reporter | `c2hunter` |
| Tags | `Mirai, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89e6bc8fb7acd9603e1c88daebf75206` |
| SHA-1 | `9eef8151d3c7336b9118a9853c5535f30f5e84d8` |
| SHA-256 | `f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2` |
| SHA3-384 | `16f0a1dd6ac6bb16eb7b5d242b6b6162d4f7c5d648124b4860182bfd3c3449a3aaccd0d80d041f189f8c3466ab0f54c7` |
| TLSH | `T1822121F5FA31ED3BB46948BD780CA46A9DC34C7F05023A9694A7AC24752ED4DB11CB32` |
| SSDEEP | `24:SPH6P66LSxGYF5MPnvu0XGixTpGek0G2GJHEn:Sf6PVSJSfGeGilYJ2GdEn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_f7413514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2"
    family = "Mirai"
    file_name = "f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2"
    file_type = "sh"
    first_seen = "2026-10-04 19:51:50"
  condition:
    hash.sha256(0, filesize) == "f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2"
}
```

### Sample 100: `55e0b73ee147b066`

| Field | Value |
|---|---|
| SHA-256 | `55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db` |
| Family label | `unknown` |
| File name | `55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db.dll` |
| File type | `exe` |
| First seen | `2026-10-04 19:49:44` |
| Reporter | `Kejult` |
| Tags | `dll, exe, loader, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad5cbdadf60b07415f5d73bde2c1ac9d` |
| SHA-1 | `2ff6b97208dad307f4a6a2f073762de0199363c1` |
| SHA-256 | `55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db` |
| SHA3-384 | `36d6032d583ac6616645f63fa07d6c31cf7c865ad67a4cd2e03888bc3d4e4469b1e30f8834d15f7e28b83d770e599c73` |
| IMPHASH | `27a4cd09447e656214fae0e4acb6e5ac` |
| TLSH | `T10E657BE86D5F5EA5FC12423BD83A0157ABF834C114F8E3922A5EBEA039338857D74197` |
| SSDEEP | `12288:KkclmEh+U7uM1PsEItzBXC8SF7AR9qrVKtnP3su6MVWhCxy67m1AX/tAAnJYBabm:Alhh+U6GuCHUR9qJY/siB4Gld` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_55e0b73e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db"
    family = "unknown"
    file_name = "55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db.dll"
    file_type = "exe"
    first_seen = "2026-10-04 19:49:44"
  condition:
    hash.sha256(0, filesize) == "55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db"
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
 * Generated: 2026-10-05T05:52:00.129428+00:00
 */

rule MalwareBazaar_RemcosRAT_001_f88971f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f88971f2b24f63bcb40e9a01ac8bc79850c9ea0410eb2f11ad5400cea34553da"
    family = "RemcosRAT"
    file_name = "IMG-Bill - Ref#843993400 New GROUP BOOKING - SOA.r00"
    file_type = "r00"
    first_seen = "2026-10-05 05:30:55"
  condition:
    hash.sha256(0, filesize) == "f88971f2b24f63bcb40e9a01ac8bc79850c9ea0410eb2f11ad5400cea34553da"
}

rule MalwareBazaar_unknown_002_cf024ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf024ccc3be3c078e5d34d4e5543068b8d3faac8f3ea3e3e7db614193397d886"
    family = "unknown"
    file_name = "tux-typing_QRi-mp3.exe"
    file_type = "exe"
    first_seen = "2026-10-05 05:29:08"
  condition:
    hash.sha256(0, filesize) == "cf024ccc3be3c078e5d34d4e5543068b8d3faac8f3ea3e3e7db614193397d886"
}

rule MalwareBazaar_unknown_003_885bf8ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "885bf8bae75d79f0911beb71b29caa16e8fdfdb0ab7115164ce1dc3c1951b6c6"
    family = "unknown"
    file_name = "885bf8bae75d79f0.bin"
    file_type = "elf"
    first_seen = "2026-10-05 05:25:56"
  condition:
    hash.sha256(0, filesize) == "885bf8bae75d79f0911beb71b29caa16e8fdfdb0ab7115164ce1dc3c1951b6c6"
}

rule MalwareBazaar_Formbook_004_a0aaff29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0aaff2946ba2bf57f5e94c081bf289a8ddb7f2edee21ba0be9796c769946f76"
    family = "Formbook"
    file_name = "FLF7997_SHIPMENT_DETAILS.com"
    file_type = "exe"
    first_seen = "2026-10-05 05:23:24"
  condition:
    hash.sha256(0, filesize) == "a0aaff2946ba2bf57f5e94c081bf289a8ddb7f2edee21ba0be9796c769946f76"
}

rule MalwareBazaar_unknown_005_dad6d444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dad6d4446092e2c99d3ad7ffbf39adb1757c282f4ac7bc2407132882311e3c1e"
    family = "unknown"
    file_name = "temp.hta"
    file_type = "hta"
    first_seen = "2026-10-05 05:18:45"
  condition:
    hash.sha256(0, filesize) == "dad6d4446092e2c99d3ad7ffbf39adb1757c282f4ac7bc2407132882311e3c1e"
}

rule MalwareBazaar_Mirai_006_d25a9db2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754"
    family = "Mirai"
    file_name = "d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754"
    file_type = "elf"
    first_seen = "2026-10-05 05:17:16"
  condition:
    hash.sha256(0, filesize) == "d25a9db2c0a77a8ab9ff136ace0bb8c840e85f36e68ff38a018014cfb1338754"
}

rule MalwareBazaar_unknown_007_af1615e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af1615e256d0847216db684529c49c5edd93bc86960c9df82258ba2255447b1f"
    family = "unknown"
    file_name = "ps_s1zdQ12P3Oik_1791176539862.ps1"
    file_type = "ps1"
    first_seen = "2026-10-05 05:14:49"
  condition:
    hash.sha256(0, filesize) == "af1615e256d0847216db684529c49c5edd93bc86960c9df82258ba2255447b1f"
}

rule MalwareBazaar_unknown_008_643f1129
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "643f1129eb68d2ba93306bdf17ed1636d81de9f95b2a57a6ea7ed942565247db"
    family = "unknown"
    file_name = "ttt.hta"
    file_type = "hta"
    first_seen = "2026-10-05 05:14:44"
  condition:
    hash.sha256(0, filesize) == "643f1129eb68d2ba93306bdf17ed1636d81de9f95b2a57a6ea7ed942565247db"
}

rule MalwareBazaar_unknown_009_c3d3575f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3d3575f71a08110a2131bd27ddbf07fd86fec364d91895460b02c19c12db83b"
    family = "unknown"
    file_name = "платеж № 0086.pdf.js"
    file_type = "js"
    first_seen = "2026-10-05 05:14:04"
  condition:
    hash.sha256(0, filesize) == "c3d3575f71a08110a2131bd27ddbf07fd86fec364d91895460b02c19c12db83b"
}

rule MalwareBazaar_Mirai_010_cb06b7dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d"
    family = "Mirai"
    file_name = "cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d"
    file_type = "elf"
    first_seen = "2026-10-05 04:17:14"
  condition:
    hash.sha256(0, filesize) == "cb06b7dc4bcdf7ce1ac83fdd17bb2638bf3cefcae956ee053899b30a31a97d8d"
}

rule MalwareBazaar_VShell_011_a61ba4f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9"
    family = "VShell"
    file_name = "a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9.exe"
    file_type = "exe"
    first_seen = "2026-10-05 04:13:52"
  condition:
    hash.sha256(0, filesize) == "a61ba4f611fc68f33bbd445ab53b7d8d3fc373746d99ae264d77961a52a071e9"
}

rule MalwareBazaar_Mirai_012_c63226d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c63226d1962d07fcb5303ca2b8e0d82aa6468aed86050197db502525654cf095"
    family = "Mirai"
    file_name = "jack5tr.sh"
    file_type = "sh"
    first_seen = "2026-10-05 04:04:53"
  condition:
    hash.sha256(0, filesize) == "c63226d1962d07fcb5303ca2b8e0d82aa6468aed86050197db502525654cf095"
}

rule MalwareBazaar_unknown_013_36a048b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36a048b70f0add874047b8b9e794182497fe7a0580e9a0a4eb3638cbf0111a21"
    family = "unknown"
    file_name = "eclipse.sh"
    file_type = "sh"
    first_seen = "2026-10-05 04:00:11"
  condition:
    hash.sha256(0, filesize) == "36a048b70f0add874047b8b9e794182497fe7a0580e9a0a4eb3638cbf0111a21"
}

rule MalwareBazaar_Mirai_014_1d6fd65e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d6fd65e639d9a3ac93a8c15bf2d39f518b27ff34bbb8b806fc16a1435948a7f"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-10-05 04:00:09"
  condition:
    hash.sha256(0, filesize) == "1d6fd65e639d9a3ac93a8c15bf2d39f518b27ff34bbb8b806fc16a1435948a7f"
}

rule MalwareBazaar_Mirai_015_3baf1b93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3baf1b9349f0b271860e300c2e61f34a3ea0ceed25e518b08db9274a730eabc9"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-10-05 04:00:06"
  condition:
    hash.sha256(0, filesize) == "3baf1b9349f0b271860e300c2e61f34a3ea0ceed25e518b08db9274a730eabc9"
}

rule MalwareBazaar_unknown_016_ffa91bd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffa91bd5a14c9171559048f3f5bb6e76d9224e106de839c13dbf4843c313e763"
    family = "unknown"
    file_name = "eclipse.mipsel"
    file_type = "elf"
    first_seen = "2026-10-05 04:00:04"
  condition:
    hash.sha256(0, filesize) == "ffa91bd5a14c9171559048f3f5bb6e76d9224e106de839c13dbf4843c313e763"
}

rule MalwareBazaar_Gafgyt_017_46db514c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46db514c0791f4093050cad13f69dd6cf207887992104b57ba3bca38d38ba14c"
    family = "Gafgyt"
    file_name = "46db514c0791f409.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:37"
  condition:
    hash.sha256(0, filesize) == "46db514c0791f4093050cad13f69dd6cf207887992104b57ba3bca38d38ba14c"
}

rule MalwareBazaar_Gafgyt_018_f7a1fa34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a1fa3463a548743ef3748dad33f678356bd659405e4f412d85cdabb9929e45"
    family = "Gafgyt"
    file_name = "f7a1fa3463a54874.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:28"
  condition:
    hash.sha256(0, filesize) == "f7a1fa3463a548743ef3748dad33f678356bd659405e4f412d85cdabb9929e45"
}

rule MalwareBazaar_Gafgyt_019_35d2c346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d2c3464b1b345e0bf5711b845abd988435bb2da9b452a0de44f99745f3d62c"
    family = "Gafgyt"
    file_name = "35d2c3464b1b345e.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:19"
  condition:
    hash.sha256(0, filesize) == "35d2c3464b1b345e0bf5711b845abd988435bb2da9b452a0de44f99745f3d62c"
}

rule MalwareBazaar_Gafgyt_020_2bfc0f1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bfc0f1dbec327a29e9fd26ba97dde795ae768382cb64ffecf694a111483cc6a"
    family = "Gafgyt"
    file_name = "2bfc0f1dbec327a2.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:10"
  condition:
    hash.sha256(0, filesize) == "2bfc0f1dbec327a29e9fd26ba97dde795ae768382cb64ffecf694a111483cc6a"
}

rule MalwareBazaar_Gafgyt_021_da6a531b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da6a531b019998fd3e7340998e756ea9cf7ea6974f2df0770b67fed55bddedf8"
    family = "Gafgyt"
    file_name = "da6a531b019998fd.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:25:01"
  condition:
    hash.sha256(0, filesize) == "da6a531b019998fd3e7340998e756ea9cf7ea6974f2df0770b67fed55bddedf8"
}

rule MalwareBazaar_Mirai_022_0b44e0e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b44e0e5640696e069413aebe9ba4c1f116f51b79277e27a9827addb5a3b5b74"
    family = "Mirai"
    file_name = "0b44e0e5640696e0.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:24:52"
  condition:
    hash.sha256(0, filesize) == "0b44e0e5640696e069413aebe9ba4c1f116f51b79277e27a9827addb5a3b5b74"
}

rule MalwareBazaar_Mirai_023_3c29f434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c29f43472e65ea111cf6fa376ba1bd7e3d4bf3e1d2f05d44456d08b16ea1934"
    family = "Mirai"
    file_name = "3c29f43472e65ea1.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:24:43"
  condition:
    hash.sha256(0, filesize) == "3c29f43472e65ea111cf6fa376ba1bd7e3d4bf3e1d2f05d44456d08b16ea1934"
}

rule MalwareBazaar_unknown_024_d6247228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d624722887c94f66e81a1f12bbb881baa2a95d31c346f3fae2f6dbb6b0fccaa9"
    family = "unknown"
    file_name = "d624722887c94f66.bin"
    file_type = "elf"
    first_seen = "2026-10-05 03:24:35"
  condition:
    hash.sha256(0, filesize) == "d624722887c94f66e81a1f12bbb881baa2a95d31c346f3fae2f6dbb6b0fccaa9"
}

rule MalwareBazaar_Mirai_025_9ea606cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671"
    family = "Mirai"
    file_name = "9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671"
    file_type = "elf"
    first_seen = "2026-10-05 03:17:14"
  condition:
    hash.sha256(0, filesize) == "9ea606cb554ea1f869dfd2c1f16fc63abd21275d2da7e7c2f8144d599523c671"
}

rule MalwareBazaar_WannaCry_026_6d69d14d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b"
    family = "WannaCry"
    file_name = "6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b"
    file_type = "exe"
    first_seen = "2026-10-05 03:15:42"
  condition:
    hash.sha256(0, filesize) == "6d69d14d77978195334345025800554e5505d2b9158ad21d78f4b9e3c099453b"
}

rule MalwareBazaar_unknown_027_f5c8298c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93"
    family = "unknown"
    file_name = "f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93.bin"
    file_type = "apk"
    first_seen = "2026-10-05 03:13:51"
  condition:
    hash.sha256(0, filesize) == "f5c8298c37963b6db62a60c2ff7cbd51d24fe2560c8d0db1386c53e8fe92db93"
}

rule MalwareBazaar_VShell_028_75eec3fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0"
    family = "VShell"
    file_name = "75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0.exe"
    file_type = "exe"
    first_seen = "2026-10-05 03:13:41"
  condition:
    hash.sha256(0, filesize) == "75eec3fe903f215cfe790a37f77c5be5fb2ef0e9466737ffdee00557acf923f0"
}

rule MalwareBazaar_Mirai_029_576fe033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462"
    family = "Mirai"
    file_name = "576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462.elf"
    file_type = "elf"
    first_seen = "2026-10-05 02:54:56"
  condition:
    hash.sha256(0, filesize) == "576fe0330127a7b33250efa3e0697928d4c515acf65bbe1d58fb87dd265b8462"
}

rule MalwareBazaar_CoinMiner_030_fb7460f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e"
    family = "CoinMiner"
    file_name = "fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e.exe"
    file_type = "exe"
    first_seen = "2026-10-05 02:35:44"
  condition:
    hash.sha256(0, filesize) == "fb7460f1febcc0f1e96f2df6c4b940f3beac750ce8cd1f30f98086400fbbe20e"
}

rule MalwareBazaar_PythonStealer_031_ed07f823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745"
    family = "PythonStealer"
    file_name = "ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745.exe"
    file_type = "exe"
    first_seen = "2026-10-05 02:23:47"
  condition:
    hash.sha256(0, filesize) == "ed07f823263ca2ffc386aec71230faea469ce8638b329176a02fe73952c78745"
}

rule MalwareBazaar_unknown_032_0ea91c69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ea91c691e0e6cabb40dbe214b536081c9b4ca2012927fea88fb40b33bfd42df"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-10-05 02:22:20"
  condition:
    hash.sha256(0, filesize) == "0ea91c691e0e6cabb40dbe214b536081c9b4ca2012927fea88fb40b33bfd42df"
}

rule MalwareBazaar_Mirai_033_dbe19861
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008"
    family = "Mirai"
    file_name = "dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008"
    file_type = "elf"
    first_seen = "2026-10-05 02:17:14"
  condition:
    hash.sha256(0, filesize) == "dbe19861490e9f9bdb39e7c35a2f09c9c67e8fb9c6343bc3937ef321388ba008"
}

rule MalwareBazaar_unknown_034_d5aa43a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e"
    family = "unknown"
    file_name = "d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e.dll"
    file_type = "dll"
    first_seen = "2026-10-05 01:55:55"
  condition:
    hash.sha256(0, filesize) == "d5aa43a733cb278791a8f543bc5bac8d47bdee7e4a449c5d26297bcdb686ba4e"
}

rule MalwareBazaar_unknown_035_062aca87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d"
    family = "unknown"
    file_name = "062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d.dll"
    file_type = "exe"
    first_seen = "2026-10-05 01:55:41"
  condition:
    hash.sha256(0, filesize) == "062aca87d292a3f462c1aa7cd016d2daf52eeb7503d335fbca6807b77105688d"
}

rule MalwareBazaar_unknown_036_9fc23681
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8"
    family = "unknown"
    file_name = "9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8.dll"
    file_type = "dll"
    first_seen = "2026-10-05 01:55:26"
  condition:
    hash.sha256(0, filesize) == "9fc2368188b4ea8c90ae7d8e4803170d873279b93f74e16b4d2f24a9525421a8"
}

rule MalwareBazaar_Mirai_037_c0726530
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c072653018239d92e9cd55e62813d712dec27ebb0a4bf17cf0398fc5d5a905cf"
    family = "Mirai"
    file_name = "winki.arm6"
    file_type = "elf"
    first_seen = "2026-10-05 01:53:23"
  condition:
    hash.sha256(0, filesize) == "c072653018239d92e9cd55e62813d712dec27ebb0a4bf17cf0398fc5d5a905cf"
}

rule MalwareBazaar_Mirai_038_eff3f4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff3f4ab2ef40f7ab1f1740ad7c22556a403a7c126c93799c419997be74b6575"
    family = "Mirai"
    file_name = "winki.mips"
    file_type = "elf"
    first_seen = "2026-10-05 01:53:21"
  condition:
    hash.sha256(0, filesize) == "eff3f4ab2ef40f7ab1f1740ad7c22556a403a7c126c93799c419997be74b6575"
}

rule MalwareBazaar_Mirai_039_cc4638f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4638f75f5d55aca03e3d3d3b9c571c0899def48cb95887a2dbb11574e02e1a"
    family = "Mirai"
    file_name = "winki.ppc"
    file_type = "elf"
    first_seen = "2026-10-05 01:53:17"
  condition:
    hash.sha256(0, filesize) == "cc4638f75f5d55aca03e3d3d3b9c571c0899def48cb95887a2dbb11574e02e1a"
}

rule MalwareBazaar_Mirai_040_ead87b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ead87b575e540b6f5d5757d1c8bda695fe67be92b17e252106651d750e4744e6"
    family = "Mirai"
    file_name = "winki.arm7"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:53"
  condition:
    hash.sha256(0, filesize) == "ead87b575e540b6f5d5757d1c8bda695fe67be92b17e252106651d750e4744e6"
}

rule MalwareBazaar_Mirai_041_5718c56f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5718c56f7378113dccb2e8aa3576a024f0f760127fd756fbfac239ee0c62c2a6"
    family = "Mirai"
    file_name = "winki.arm"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:51"
  condition:
    hash.sha256(0, filesize) == "5718c56f7378113dccb2e8aa3576a024f0f760127fd756fbfac239ee0c62c2a6"
}

rule MalwareBazaar_Mirai_042_dc01fe12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc01fe12438a973d7288c5fa2704df06d92df1c7b60f98e26a13186396b6b6d5"
    family = "Mirai"
    file_name = "winki.mpsl"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:48"
  condition:
    hash.sha256(0, filesize) == "dc01fe12438a973d7288c5fa2704df06d92df1c7b60f98e26a13186396b6b6d5"
}

rule MalwareBazaar_Mirai_043_361699bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "361699bd9c276fdbef11bc135de69dc2b2dc423c7460f96b5f42cf7eae2c2e83"
    family = "Mirai"
    file_name = "winki.m68k"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:46"
  condition:
    hash.sha256(0, filesize) == "361699bd9c276fdbef11bc135de69dc2b2dc423c7460f96b5f42cf7eae2c2e83"
}

rule MalwareBazaar_unknown_044_990fa84a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e"
    family = "unknown"
    file_name = "990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e.exe"
    file_type = "exe"
    first_seen = "2026-10-05 01:48:45"
  condition:
    hash.sha256(0, filesize) == "990fa84a88d86a9dac77882de2629849222c37d13b433ccce41bc6cf7780af6e"
}

rule MalwareBazaar_Mirai_045_e2546433
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2546433e7d686414916ec02c249e99b2e57e10823c2ca8563e18ce46178a39b"
    family = "Mirai"
    file_name = "winki.arm5"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:43"
  condition:
    hash.sha256(0, filesize) == "e2546433e7d686414916ec02c249e99b2e57e10823c2ca8563e18ce46178a39b"
}

rule MalwareBazaar_Mirai_046_f6bf1b51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6bf1b51a3526dfe3178b81b6670491e745dc499987a100ac942de895ed84a21"
    family = "Mirai"
    file_name = "winki.sh4"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:41"
  condition:
    hash.sha256(0, filesize) == "f6bf1b51a3526dfe3178b81b6670491e745dc499987a100ac942de895ed84a21"
}

rule MalwareBazaar_Mirai_047_42aa476e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42aa476e9677d875f15f6e09c8cdb40a461a2db58dadcb9b6c5adfd4a796d948"
    family = "Mirai"
    file_name = "winki.x86"
    file_type = "elf"
    first_seen = "2026-10-05 01:48:39"
  condition:
    hash.sha256(0, filesize) == "42aa476e9677d875f15f6e09c8cdb40a461a2db58dadcb9b6c5adfd4a796d948"
}

rule MalwareBazaar_AgentTesla_048_f61318a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f61318a710fa4fbd24b163df3a089bfcef25b04da61880e132064ec5c5d7ed5e"
    family = "AgentTesla"
    file_name = "revised Invoice.js"
    file_type = "js"
    first_seen = "2026-10-05 01:32:52"
  condition:
    hash.sha256(0, filesize) == "f61318a710fa4fbd24b163df3a089bfcef25b04da61880e132064ec5c5d7ed5e"
}

rule MalwareBazaar_Mirai_049_2571f3fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1"
    family = "Mirai"
    file_name = "2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1"
    file_type = "elf"
    first_seen = "2026-10-05 01:17:16"
  condition:
    hash.sha256(0, filesize) == "2571f3fa3054da51c16e698cb1578ab9405c80a34172874bdb56dd7df98b0be1"
}

rule MalwareBazaar_unknown_050_b7689b12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7689b12e1b94e628c8398ec86a6ad5ba564f107c5085464f3d03f408959545b"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-05 00:42:15"
  condition:
    hash.sha256(0, filesize) == "b7689b12e1b94e628c8398ec86a6ad5ba564f107c5085464f3d03f408959545b"
}

rule MalwareBazaar_unknown_051_06f7f11c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06f7f11cfc2c401875f2f9aef30e2176ad3520d0d309c88361b2202ad67099a2"
    family = "unknown"
    file_name = "temp.hta"
    file_type = "hta"
    first_seen = "2026-10-05 00:42:12"
  condition:
    hash.sha256(0, filesize) == "06f7f11cfc2c401875f2f9aef30e2176ad3520d0d309c88361b2202ad67099a2"
}

rule MalwareBazaar_Mirai_052_d07b4210
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d07b4210db5c2610daedc2831915af6c4e9f7966739ff789a0af2a18bb5dca66"
    family = "Mirai"
    file_name = "kushnet.x64-test"
    file_type = "elf"
    first_seen = "2026-10-05 00:38:02"
  condition:
    hash.sha256(0, filesize) == "d07b4210db5c2610daedc2831915af6c4e9f7966739ff789a0af2a18bb5dca66"
}

rule MalwareBazaar_Mirai_053_7850fe83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7850fe83806399284d1b643547b6cdbfa3f1cc7413550514df0548b7eb1d3066"
    family = "Mirai"
    file_name = "kushnet.arm6"
    file_type = "elf"
    first_seen = "2026-10-05 00:37:59"
  condition:
    hash.sha256(0, filesize) == "7850fe83806399284d1b643547b6cdbfa3f1cc7413550514df0548b7eb1d3066"
}

rule MalwareBazaar_unknown_054_cc16c460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc16c460ded51ac533139917d16ef09eea894fd4058618c97d511de7722c460f"
    family = "unknown"
    file_name = "macho_cc16c460ded5.bin"
    file_type = "macho"
    first_seen = "2026-10-05 00:34:24"
  condition:
    hash.sha256(0, filesize) == "cc16c460ded51ac533139917d16ef09eea894fd4058618c97d511de7722c460f"
}

rule MalwareBazaar_Mirai_055_f5a7d9d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5a7d9d169aff0adc6b109a35c5ad7f0f2fce8ce1d4425daaa405507181048ef"
    family = "Mirai"
    file_name = "kushnet.mipsel"
    file_type = "elf"
    first_seen = "2026-10-05 00:33:59"
  condition:
    hash.sha256(0, filesize) == "f5a7d9d169aff0adc6b109a35c5ad7f0f2fce8ce1d4425daaa405507181048ef"
}

rule MalwareBazaar_unknown_056_889582f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889582f9f03be880d3d9d2708561ad0241f8698df8537edbd0a5dc4fa8b42627"
    family = "unknown"
    file_name = "macho_889582f9f03b.bin"
    file_type = "macho"
    first_seen = "2026-10-05 00:24:43"
  condition:
    hash.sha256(0, filesize) == "889582f9f03be880d3d9d2708561ad0241f8698df8537edbd0a5dc4fa8b42627"
}

rule MalwareBazaar_Mirai_057_f380544d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f380544dc352ff8d00a9fa20722c12345241fd7c148b66cb8c0bb80f6917ccff"
    family = "Mirai"
    file_name = "f380544dc352ff8d.bin"
    file_type = "elf"
    first_seen = "2026-10-05 00:24:13"
  condition:
    hash.sha256(0, filesize) == "f380544dc352ff8d00a9fa20722c12345241fd7c148b66cb8c0bb80f6917ccff"
}

rule MalwareBazaar_Mirai_058_2721dbcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2721dbcd118b8c4f018ff09a96c10bf5e60ee537a4ccc9c83ed824d90d49af14"
    family = "Mirai"
    file_name = "2721dbcd118b8c4f.bin"
    file_type = "elf"
    first_seen = "2026-10-05 00:24:04"
  condition:
    hash.sha256(0, filesize) == "2721dbcd118b8c4f018ff09a96c10bf5e60ee537a4ccc9c83ed824d90d49af14"
}

rule MalwareBazaar_Mirai_059_507611a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "507611a45de2fa9f20c1e26e4274b655faf7f47cb2688a1782da25604a2e34c6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-05 00:21:54"
  condition:
    hash.sha256(0, filesize) == "507611a45de2fa9f20c1e26e4274b655faf7f47cb2688a1782da25604a2e34c6"
}

rule MalwareBazaar_Mirai_060_a1b9cf98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1b9cf98985d4b1a3b571828bfec90ab03727a9c43f88adfe58d096dcb8ec568"
    family = "Mirai"
    file_name = "kushnet.m68k"
    file_type = "elf"
    first_seen = "2026-10-05 00:17:58"
  condition:
    hash.sha256(0, filesize) == "a1b9cf98985d4b1a3b571828bfec90ab03727a9c43f88adfe58d096dcb8ec568"
}

rule MalwareBazaar_Mirai_061_b2caaa4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0"
    family = "Mirai"
    file_name = "b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0"
    file_type = "elf"
    first_seen = "2026-10-05 00:17:14"
  condition:
    hash.sha256(0, filesize) == "b2caaa4db2b844eaaed289705e5efe889c05f45a212bfcc44d41bb39726cf0c0"
}

rule MalwareBazaar_unknown_062_998bed38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998bed38abfa7e807bb2c8d0e0d54cb499c56f0583a99984ac24341b51c4d9e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-05 00:15:25"
  condition:
    hash.sha256(0, filesize) == "998bed38abfa7e807bb2c8d0e0d54cb499c56f0583a99984ac24341b51c4d9e4"
}

rule MalwareBazaar_unknown_063_2f86a4fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f86a4fe00548a8ac9cf5941bfcece12e8d1f815ce720bbd02a8fa7b93ef015c"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-05 00:06:06"
  condition:
    hash.sha256(0, filesize) == "2f86a4fe00548a8ac9cf5941bfcece12e8d1f815ce720bbd02a8fa7b93ef015c"
}

rule MalwareBazaar_Mirai_064_b126a568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b126a5682d497b3f0c2c4d6c34c52091ed973e475ac7019f65f941d9690efe27"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-05 00:06:04"
  condition:
    hash.sha256(0, filesize) == "b126a5682d497b3f0c2c4d6c34c52091ed973e475ac7019f65f941d9690efe27"
}

rule MalwareBazaar_Mirai_065_8a77b02b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a77b02b82e8759b6c502d656995603b249284eb9651d41f2c9517acaa65f6da"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-05 00:01:55"
  condition:
    hash.sha256(0, filesize) == "8a77b02b82e8759b6c502d656995603b249284eb9651d41f2c9517acaa65f6da"
}

rule MalwareBazaar_Mirai_066_a7997215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7997215ca6cfe70aa70cdb4225abc514e650307e6f6e2cf48a565d7b11a56af"
    family = "Mirai"
    file_name = "kushnet.arm7"
    file_type = "elf"
    first_seen = "2026-10-05 00:01:53"
  condition:
    hash.sha256(0, filesize) == "a7997215ca6cfe70aa70cdb4225abc514e650307e6f6e2cf48a565d7b11a56af"
}

rule MalwareBazaar_unknown_067_5c48e2f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c48e2f8fa87d70064e5a6aaf4d1d8fb78a76633f6b24927e3866b17d05bb9e0"
    family = "unknown"
    file_name = "Captcha.hta"
    file_type = "hta"
    first_seen = "2026-10-04 23:49:49"
  condition:
    hash.sha256(0, filesize) == "5c48e2f8fa87d70064e5a6aaf4d1d8fb78a76633f6b24927e3866b17d05bb9e0"
}

rule MalwareBazaar_Mirai_068_2a82f1ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a82f1ad66901ddb28bbf12e999bf44417576ed3ce0ed264275ec6f2c64f8313"
    family = "Mirai"
    file_name = "kushnet.arm5"
    file_type = "elf"
    first_seen = "2026-10-04 23:49:47"
  condition:
    hash.sha256(0, filesize) == "2a82f1ad66901ddb28bbf12e999bf44417576ed3ce0ed264275ec6f2c64f8313"
}

rule MalwareBazaar_Mirai_069_6405edc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6405edc4312d014d21abcc0ebadc11dfdf34a899ce679c63bc8337e85088cfe8"
    family = "Mirai"
    file_name = "kushnet.x32"
    file_type = "elf"
    first_seen = "2026-10-04 23:49:45"
  condition:
    hash.sha256(0, filesize) == "6405edc4312d014d21abcc0ebadc11dfdf34a899ce679c63bc8337e85088cfe8"
}

rule MalwareBazaar_unknown_070_467cef31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467cef311f7c72e1bbb8468c9c4dfe1cab9aa6dd6d93209f18f22c91441dd077"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 23:46:00"
  condition:
    hash.sha256(0, filesize) == "467cef311f7c72e1bbb8468c9c4dfe1cab9aa6dd6d93209f18f22c91441dd077"
}

rule MalwareBazaar_unknown_071_24fabf58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24fabf58e8133d7d920622e7beacde41a0340d77e91529ab9822929ebecc4a3b"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-04 23:45:25"
  condition:
    hash.sha256(0, filesize) == "24fabf58e8133d7d920622e7beacde41a0340d77e91529ab9822929ebecc4a3b"
}

rule MalwareBazaar_Mirai_072_ce93d122
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce93d122add841b2d48c2554309d9572247e362a0f868d7d5e61e741bbce176f"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-04 23:45:22"
  condition:
    hash.sha256(0, filesize) == "ce93d122add841b2d48c2554309d9572247e362a0f868d7d5e61e741bbce176f"
}

rule MalwareBazaar_Mirai_073_2be178ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2be178ca19dddfeaf678fe36d2a01c11c3261811de079d6459ba4c9bcd916171"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-04 23:45:19"
  condition:
    hash.sha256(0, filesize) == "2be178ca19dddfeaf678fe36d2a01c11c3261811de079d6459ba4c9bcd916171"
}

rule MalwareBazaar_Mirai_074_9658a7f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9658a7f443c53943fea55027529a8fab90cd2ef118dddd37ab08544997e64abc"
    family = "Mirai"
    file_name = "kushnet.mips"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:43"
  condition:
    hash.sha256(0, filesize) == "9658a7f443c53943fea55027529a8fab90cd2ef118dddd37ab08544997e64abc"
}

rule MalwareBazaar_unknown_075_eedc958f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eedc958f4c7862ef03e6d15e70ff7ad4ac34c4733a8cb3c8ceebcb68836d7b67"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:41"
  condition:
    hash.sha256(0, filesize) == "eedc958f4c7862ef03e6d15e70ff7ad4ac34c4733a8cb3c8ceebcb68836d7b67"
}

rule MalwareBazaar_Mirai_076_3a0fcd09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a0fcd09f8c03b59a951a7cbbac7c53b20185188575e694aeac09f995a143a42"
    family = "Mirai"
    file_name = "kushnet.ppc440"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:38"
  condition:
    hash.sha256(0, filesize) == "3a0fcd09f8c03b59a951a7cbbac7c53b20185188575e694aeac09f995a143a42"
}

rule MalwareBazaar_Mirai_077_17c9b7dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17c9b7dd459078cf11edb629a2ff32dfc0313e4d60a779c40f0783fcddd20084"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-04 23:40:36"
  condition:
    hash.sha256(0, filesize) == "17c9b7dd459078cf11edb629a2ff32dfc0313e4d60a779c40f0783fcddd20084"
}

rule MalwareBazaar_ConnectWise_078_0e385560
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604"
    family = "ConnectWise"
    file_name = "0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604.msi"
    file_type = "msi"
    first_seen = "2026-10-04 23:33:47"
  condition:
    hash.sha256(0, filesize) == "0e38556099f10acb59a46f5876dedaa2d8aac0cad7d65f02d900a3275f74e604"
}

rule MalwareBazaar_unknown_079_f02c012b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f02c012b21fbd9aa636afc247ff6677a6e635845bb36ab4d1e0f1b404af27fa1"
    family = "unknown"
    file_name = "Real Executor.exe"
    file_type = "exe"
    first_seen = "2026-10-04 23:23:45"
  condition:
    hash.sha256(0, filesize) == "f02c012b21fbd9aa636afc247ff6677a6e635845bb36ab4d1e0f1b404af27fa1"
}

rule MalwareBazaar_unknown_080_0336851d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0336851d92948169ecd1e2499c21ab87299055af61e55fe1c1e1e7d83d3d1278"
    family = "unknown"
    file_name = "Contact Information Regarding Cooperation Armaments and Military Attache Matters.html"
    file_type = "html"
    first_seen = "2026-10-04 23:22:01"
  condition:
    hash.sha256(0, filesize) == "0336851d92948169ecd1e2499c21ab87299055af61e55fe1c1e1e7d83d3d1278"
}

rule MalwareBazaar_Mirai_081_cf68e31b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2"
    family = "Mirai"
    file_name = "cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2"
    file_type = "elf"
    first_seen = "2026-10-04 23:17:15"
  condition:
    hash.sha256(0, filesize) == "cf68e31b765dca742813f6d799d42a3aa0f5db390dfb787239a5c50d127b9fa2"
}

rule MalwareBazaar_unknown_082_c8e0831a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8e0831ac41f27233f76ee11b3b27284be0c055c1598f5aaa644aea46cdd95b8"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-04 23:00:39"
  condition:
    hash.sha256(0, filesize) == "c8e0831ac41f27233f76ee11b3b27284be0c055c1598f5aaa644aea46cdd95b8"
}

rule MalwareBazaar_Mirai_083_7e54a364
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c"
    family = "Mirai"
    file_name = "7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c"
    file_type = "elf"
    first_seen = "2026-10-04 22:17:14"
  condition:
    hash.sha256(0, filesize) == "7e54a3647039544393337ae637a5104331a37178dda9ee3242ac7097968f1d6c"
}

rule MalwareBazaar_SilentNet_084_2e716444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e716444b93e04a56e01fa485e7cbe32f5f601d1d183e112d29ea5cd83bad6f6"
    family = "SilentNet"
    file_name = "Launcher.exe"
    file_type = "exe"
    first_seen = "2026-10-04 22:10:20"
  condition:
    hash.sha256(0, filesize) == "2e716444b93e04a56e01fa485e7cbe32f5f601d1d183e112d29ea5cd83bad6f6"
}

rule MalwareBazaar_unknown_085_9a1c175c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a1c175c7d56808a694be3939e0cf98d8097efd8f46f8fd317aa226171b5c9cd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 21:53:00"
  condition:
    hash.sha256(0, filesize) == "9a1c175c7d56808a694be3939e0cf98d8097efd8f46f8fd317aa226171b5c9cd"
}

rule MalwareBazaar_RemusStealer_086_d9d6f4d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d6f4d04fb0f2e2d16bf729035b2eb3dc7d7a160eddf9b43b6d5c794e77e4d1"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 21:40:52"
  condition:
    hash.sha256(0, filesize) == "d9d6f4d04fb0f2e2d16bf729035b2eb3dc7d7a160eddf9b43b6d5c794e77e4d1"
}

rule MalwareBazaar_unknown_087_8b1b1714
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b1b1714d9544d86284accdd3240df5ef641cf5504f4c8baebec5387e966524f"
    family = "unknown"
    file_name = "Setup_winletlatst安装.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:31:42"
  condition:
    hash.sha256(0, filesize) == "8b1b1714d9544d86284accdd3240df5ef641cf5504f4c8baebec5387e966524f"
}

rule MalwareBazaar_unknown_088_25a546a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25a546a305fbfe3b05f90139fe3f007818e5668192c6b74a9ea861b496de6566"
    family = "unknown"
    file_name = "quickq.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:30:50"
  condition:
    hash.sha256(0, filesize) == "25a546a305fbfe3b05f90139fe3f007818e5668192c6b74a9ea861b496de6566"
}

rule MalwareBazaar_Gh0stRAT_089_f31ece43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f31ece43389d70c6351fa607e08e31a1e11f5d9d77968f4b515c833a1628973a"
    family = "Gh0stRAT"
    file_name = "lightxtreme.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:29:35"
  condition:
    hash.sha256(0, filesize) == "f31ece43389d70c6351fa607e08e31a1e11f5d9d77968f4b515c833a1628973a"
}

rule MalwareBazaar_Gh0stRAT_090_ba5088e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba5088e6fff5b63a2316fc273029bb651436be91618ba53425e24e23c798ab2a"
    family = "Gh0stRAT"
    file_name = "goujijiasuqi.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:28:44"
  condition:
    hash.sha256(0, filesize) == "ba5088e6fff5b63a2316fc273029bb651436be91618ba53425e24e23c798ab2a"
}

rule MalwareBazaar_Gh0stRAT_091_01dec44e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01dec44e70c5c84d2e790a3f2bd4e8613ba82ebd1d13bfb9e4df20ea476ca559"
    family = "Gh0stRAT"
    file_name = "flclash.exe"
    file_type = "exe"
    first_seen = "2026-10-04 21:28:02"
  condition:
    hash.sha256(0, filesize) == "01dec44e70c5c84d2e790a3f2bd4e8613ba82ebd1d13bfb9e4df20ea476ca559"
}

rule MalwareBazaar_Mirai_092_73fa3523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae"
    family = "Mirai"
    file_name = "73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae"
    file_type = "elf"
    first_seen = "2026-10-04 21:17:14"
  condition:
    hash.sha256(0, filesize) == "73fa3523e75f87922d8927fa1b912fdac512ef09c12b8c7709df1b4eb40782ae"
}

rule MalwareBazaar_Mirai_093_a62ae903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82"
    family = "Mirai"
    file_name = "a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82"
    file_type = "elf"
    first_seen = "2026-10-04 20:17:14"
  condition:
    hash.sha256(0, filesize) == "a62ae903603179c7f3cca4548bd2b46fdb4e13b3896f1e9a529813e13601ef82"
}

rule MalwareBazaar_unknown_094_c34ebc38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34ebc389e99c4bfbddf726fc6f357aa625efb8afdf2abceef9454ab4026d687"
    family = "unknown"
    file_name = "7c1cc22a11e0d0a49ce86d1e5a2943922555860450d7ad6559ca7bc7c4eec99c.zip"
    file_type = "zip"
    first_seen = "2026-10-04 20:12:42"
  condition:
    hash.sha256(0, filesize) == "c34ebc389e99c4bfbddf726fc6f357aa625efb8afdf2abceef9454ab4026d687"
}

rule MalwareBazaar_unknown_095_92365a18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b"
    family = "unknown"
    file_name = "92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b.exe"
    file_type = "exe"
    first_seen = "2026-10-04 20:01:57"
  condition:
    hash.sha256(0, filesize) == "92365a186dec592d0741d2bf29cffd80029e56394311bde51d424abfdae3347b"
}

rule MalwareBazaar_Mirai_096_0b667fe4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b667fe4fc990f75d0ff341a3a8c0a6a8939006cbf74d1250e536dcaa020e262"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-10-04 20:00:27"
  condition:
    hash.sha256(0, filesize) == "0b667fe4fc990f75d0ff341a3a8c0a6a8939006cbf74d1250e536dcaa020e262"
}

rule MalwareBazaar_unknown_097_26774e49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26774e49d90c14c84cf1a99a466f22e474db036d97b05e9cdef94d7bfe49cfc0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-04 19:54:30"
  condition:
    hash.sha256(0, filesize) == "26774e49d90c14c84cf1a99a466f22e474db036d97b05e9cdef94d7bfe49cfc0"
}

rule MalwareBazaar_Mirai_098_4cd80026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11"
    family = "Mirai"
    file_name = "4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11"
    file_type = "elf"
    first_seen = "2026-10-04 19:51:58"
  condition:
    hash.sha256(0, filesize) == "4cd800261d0e873ee5c8237997707bc22174417d09e46585d136ae96a547cd11"
}

rule MalwareBazaar_Mirai_099_f7413514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2"
    family = "Mirai"
    file_name = "f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2"
    file_type = "sh"
    first_seen = "2026-10-04 19:51:50"
  condition:
    hash.sha256(0, filesize) == "f74135143232bc1ac7c8c33f3394d5ffde9bef4aa4c7f4c5ad20bcde9332f5e2"
}

rule MalwareBazaar_unknown_100_55e0b73e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db"
    family = "unknown"
    file_name = "55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db.dll"
    file_type = "exe"
    first_seen = "2026-10-04 19:49:44"
  condition:
    hash.sha256(0, filesize) == "55e0b73ee147b0661221c41a5cfbdd5204c760f0c22359596cc70e94315686db"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

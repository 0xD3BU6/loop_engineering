# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-15

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 660 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 660 |
| Unique family labels | 11 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 58 |
| Mirai | 32 |
| AsyncRAT | 2 |
| ConnectWise | 1 |
| Prometei | 1 |
| ValleyRAT | 1 |
| CoinMiner | 1 |
| Vidar | 1 |
| RustyStealer | 1 |
| njrat | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 47 |
| elf | 34 |
| sh | 7 |
| zip | 4 |
| unknown | 4 |
| vbs | 1 |
| iso | 1 |
| dll | 1 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `064726f32e709694`

| Field | Value |
|---|---|
| SHA-256 | `064726f32e709694520801994c297551e07782fb3d4d9e5c8a44cb6792d8dd02` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-15 01:36:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88f6d76dbe0367a2e90a4f7a3d561269` |
| SHA-1 | `377f0d42ad49ad6e9a1dcea55a7f168207d155c7` |
| SHA-256 | `064726f32e709694520801994c297551e07782fb3d4d9e5c8a44cb6792d8dd02` |
| SHA3-384 | `bde6f33e403c0c424c91e81ea534ef43f074a6f6d4dd7380574371516b38ec9af65d1450233df4c92ede04fd9c357f81` |
| TLSH | `T15A237D6126857C14AA99C8371D7E2F0CBDAD43E6320452EE7FCB3CF68C4A69DA10971D` |
| SSDEEP | `768:g6rDTPjH0T9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Xr3Q0cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_064726f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "064726f32e709694520801994c297551e07782fb3d4d9e5c8a44cb6792d8dd02"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 01:36:45"
  condition:
    hash.sha256(0, filesize) == "064726f32e709694520801994c297551e07782fb3d4d9e5c8a44cb6792d8dd02"
}
```

### Sample 2: `2187038e66f6ebae`

| Field | Value |
|---|---|
| SHA-256 | `2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f` |
| Family label | `unknown` |
| File name | `2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f.bin` |
| File type | `exe` |
| First seen | `2026-08-15 01:23:52` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5c0c41a5cef69021b0bf05eb5af5bc6` |
| SHA-1 | `3b6a4aa0ec409408279990f5db31859e16b24c05` |
| SHA-256 | `2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f` |
| SHA3-384 | `1513717ade894ca43c4a58bff9b5c755a2549866c387b9cce7061c758a691aa5766f9f1dfb59e918602ddc129bd81800` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E0366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaad:uc3XND1aJrCOkd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_2187038e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f"
    family = "unknown"
    file_name = "2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f.bin"
    file_type = "exe"
    first_seen = "2026-08-15 01:23:52"
  condition:
    hash.sha256(0, filesize) == "2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f"
}
```

### Sample 3: `8edbfc6979fddbb9`

| Field | Value |
|---|---|
| SHA-256 | `8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea` |
| Family label | `unknown` |
| File name | `8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea.elf` |
| File type | `elf` |
| First seen | `2026-08-15 01:19:34` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2299e8b2de540d0b80d242f216fcfdcc` |
| SHA-1 | `a99d39e7211e4ab7cad54269fed3bda080a92895` |
| SHA-256 | `8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea` |
| SHA3-384 | `c31f97c0c0b006d440fd1657f301a0184a9dcd7799829626a9bf6c7b662808aead8028d11a1db4eaa0c8e8b7ea64b2d2` |
| TLSH | `T1B3630234B701116AF816573253644BF278708BE2E72A7426D9678F91DB052F3BCA7E8C` |
| SSDEEP | `1536:NQY3xEvzte6/HpnpRqSIkPL49zM8TKv48eIEmR2ItPJfvWVJuo:NQYhEnfppHIg8KA8XEydFvWVQo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_8edbfc69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea"
    family = "unknown"
    file_name = "8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea.elf"
    file_type = "elf"
    first_seen = "2026-08-15 01:19:34"
  condition:
    hash.sha256(0, filesize) == "8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea"
}
```

### Sample 4: `839b184f7816c68f`

| Field | Value |
|---|---|
| SHA-256 | `839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd` |
| Family label | `unknown` |
| File name | `839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd.bin` |
| File type | `zip` |
| First seen | `2026-08-15 01:14:33` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8af93cca7d5ca26dd3999ff0d0d45b3` |
| SHA-1 | `3d35e287e10e5101307d125a259d3b435c3e4445` |
| SHA-256 | `839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd` |
| SHA3-384 | `188d1317b5b10ebed7d0a9f1a9895e5f97840a7e1b9714c274041881070c5c404727e5bebd292da942a0cab9830788e5` |
| TLSH | `T124A42397E39996EC88C47ABA8B2C0D0CB27CE7745CCF06A8537E5335D1688A29E0751D` |
| SSDEEP | `12288:msS5lyFd6b+6sVXkvgSe5ypqr++rVOje+yH5W:msgxi6sSvP8y+6eTH5W` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_839b184f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd"
    family = "unknown"
    file_name = "839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd.bin"
    file_type = "zip"
    first_seen = "2026-08-15 01:14:33"
  condition:
    hash.sha256(0, filesize) == "839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd"
}
```

### Sample 5: `5bd490dbc4b0aa47`

| Field | Value |
|---|---|
| SHA-256 | `5bd490dbc4b0aa47cfaba73ba2394edecbea4f0d196158512a85c2ed5521d4c5` |
| Family label | `ConnectWise` |
| File name | `Adobe_Acrobat_Update.vbs` |
| File type | `vbs` |
| First seen | `2026-08-15 00:58:29` |
| Reporter | `iamaachum` |
| Tags | `ConnectWise, ph-tech-net, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ace3b157ac92623a21051e3f536b8cf9` |
| SHA-1 | `4fc54f9b2698c61066fc3ecb671dfeefe85e6724` |
| SHA-256 | `5bd490dbc4b0aa47cfaba73ba2394edecbea4f0d196158512a85c2ed5521d4c5` |
| SHA3-384 | `fa7e4ae8385b3b250cf59eb55d4c0a5332867541ab4aeb8f3fe3d4989bf0c309773b920ca858076f1297b2a7e7980fb6` |
| TLSH | `T1F567D0616E983EB1EFE8160D90BE6F0E03F0615A2805705EEA556F4F9FF7A48440F1A7` |
| SSDEEP | `49152:bphLKehmuhkzH2ke4/P1tzvXq5gw2s7z8ufVuEHpcv+jfZ/3OZH/phLKehmuhkz9:V` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_005_5bd490db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bd490dbc4b0aa47cfaba73ba2394edecbea4f0d196158512a85c2ed5521d4c5"
    family = "ConnectWise"
    file_name = "Adobe_Acrobat_Update.vbs"
    file_type = "vbs"
    first_seen = "2026-08-15 00:58:29"
  condition:
    hash.sha256(0, filesize) == "5bd490dbc4b0aa47cfaba73ba2394edecbea4f0d196158512a85c2ed5521d4c5"
}
```

### Sample 6: `35491352181d7598`

| Field | Value |
|---|---|
| SHA-256 | `35491352181d7598270320d15f331f250c848f94b09ce008d78d901b2b5950e0` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-15 00:53:35` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d84d94f80c74358c7bb2d2794f9c452` |
| SHA-1 | `ac9b909f8218706e0f9002303bed9c8961f5fe3a` |
| SHA-256 | `35491352181d7598270320d15f331f250c848f94b09ce008d78d901b2b5950e0` |
| SHA3-384 | `ffbe41dc3f9791423b2bf8648b2b0a7097d14a903b7ea00f62a4dc03d10d91d5d7094f230e1e5aa42fac4de11a300b22` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T107E6331865E511FDEEB3413CDDE34622D57AB8780736CED78B6807BA1C431E04A7AA27` |
| SSDEEP | `393216:ieYHr26Edhvg96sY0CV8ZQ7eBej1XMCHWUjScuI3/PGTAI:i/zEjg96sY5LXMb8vH/O7` |
| ICON-DHASH | `e86865e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_35491352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35491352181d7598270320d15f331f250c848f94b09ce008d78d901b2b5950e0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-15 00:53:35"
  condition:
    hash.sha256(0, filesize) == "35491352181d7598270320d15f331f250c848f94b09ce008d78d901b2b5950e0"
}
```

### Sample 7: `0775c10d939f7b0e`

| Field | Value |
|---|---|
| SHA-256 | `0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae` |
| Family label | `unknown` |
| File name | `0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae.bin` |
| File type | `exe` |
| First seen | `2026-08-15 00:53:34` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3354ca3fec7b391f4512da8dd3421da` |
| SHA-1 | `7dba100cce3032d656b51d04f0d21497853f7f37` |
| SHA-256 | `0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae` |
| SHA3-384 | `23392a9cb5a75fc5b0325b7a72a83da1cec3b7a7534f17aa960a3a082cefbacd778251e293f713ceb130c3d74213b6de` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T16E863A17D9519CA5C096E23188A6521BBB34BC78873323D71EB0BA783F767D16E78720` |
| SSDEEP | `49152:8qQioQs5/sx6AMv3h+AR+L+zX8BNgjcqTApiZFENP/9ZwBtdWZ47YFlNJb7wSr9B:8iM/cAgLcXAvKEQhk1exaxF4/i00SNq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_0775c10d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae"
    family = "unknown"
    file_name = "0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae.bin"
    file_type = "exe"
    first_seen = "2026-08-15 00:53:34"
  condition:
    hash.sha256(0, filesize) == "0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae"
}
```

### Sample 8: `87a180e1e975b060`

| Field | Value |
|---|---|
| SHA-256 | `87a180e1e975b060f55963476f966f3c9afe8e3794cc66ed1702ea909898d663` |
| Family label | `unknown` |
| File name | `540453966.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:50:59` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-RenPyLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a525a46f4183189173d26f0d44bd90fb` |
| SHA-1 | `9b701b5bb722ef6dff33f4a99768b289c5d74c66` |
| SHA-256 | `87a180e1e975b060f55963476f966f3c9afe8e3794cc66ed1702ea909898d663` |
| SHA3-384 | `4596f08f30cdb0d4da105ab70efe0f4df142828db69d82d4a3baf6a6ddac8067cfb7e5133aca032080451347fd4cdab3` |
| IMPHASH | `cef727e2a0197bcc642be3c3ad18ac35` |
| TLSH | `T133B4E197FBD401FCD4A6827885A90B12A7F2FC112B609AEF4360558B1F676C56F3BB40` |
| SSDEEP | `6144:gV8ZxTMTJ4DXCxzxJEF7XNs/VPBIGLMkdsOiDIvx5XX1m8cdpOWRlSkT+6t86mEw:g6zTdyxz67XWtpjiCXEdpOWRFDtZmom` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_87a180e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87a180e1e975b060f55963476f966f3c9afe8e3794cc66ed1702ea909898d663"
    family = "unknown"
    file_name = "540453966.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:50:59"
  condition:
    hash.sha256(0, filesize) == "87a180e1e975b060f55963476f966f3c9afe8e3794cc66ed1702ea909898d663"
}
```

### Sample 9: `4f8b3ce56a567f4d`

| Field | Value |
|---|---|
| SHA-256 | `4f8b3ce56a567f4d1f5a3e4ef0fedcdfad707bfc1b4234397da600f8e2e32316` |
| Family label | `unknown` |
| File name | `Pro Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:34:42` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e1831dac3e7b29ce85e256af3a59bc8` |
| SHA-1 | `bcd816c8d313d033d5bbb36c6ffe89982456e7a4` |
| SHA-256 | `4f8b3ce56a567f4d1f5a3e4ef0fedcdfad707bfc1b4234397da600f8e2e32316` |
| SHA3-384 | `bebe9371c37674fe8ad2b750dd96a38ef604cf88723309e9306fa0c85b0e694fda3302c2031ec289839f52c441884ea5` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T165B55A07BE8041A5D49AE73689B74251B630BC4CC73533D72F91AAB42FB27D2A976F10` |
| SSDEEP | `24576:O+JHRUqdS2KeEUuAYsvLt68HgnZw63YJRmBAMISIlqaUY586x:fHRHdS9eRttAZwbJRiI5ke` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_4f8b3ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f8b3ce56a567f4d1f5a3e4ef0fedcdfad707bfc1b4234397da600f8e2e32316"
    family = "unknown"
    file_name = "Pro Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:34:42"
  condition:
    hash.sha256(0, filesize) == "4f8b3ce56a567f4d1f5a3e4ef0fedcdfad707bfc1b4234397da600f8e2e32316"
}
```

### Sample 10: `57478a0f3dcf4df1`

| Field | Value |
|---|---|
| SHA-256 | `57478a0f3dcf4df1c96dbb3cd9aa3b255814bd3a4185bf90ba768eb28b471797` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:32:55` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17ea6604b441e15f0e96d072aa67efe0` |
| SHA-1 | `19a544e28b2c0b70efd96ca0a8ec178c275c9bb0` |
| SHA-256 | `57478a0f3dcf4df1c96dbb3cd9aa3b255814bd3a4185bf90ba768eb28b471797` |
| SHA3-384 | `a6d046c792bd16b77b6b7edc8f1c44c81554a0b45ac97b7e70a59f82b129d139c573c1bf32a345cdb2ef110032028e7f` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1F3C55B0728704276C852E77964B72226BAB4BE48CB7973D32D51EB742F713C16EB9708` |
| SSDEEP | `24576:RZGOYVQoZjCIODw3B46zjtQ+WRKZi9whLUsaQc:aOYVQoZjM03a69WR+of` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_57478a0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57478a0f3dcf4df1c96dbb3cd9aa3b255814bd3a4185bf90ba768eb28b471797"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:32:55"
  condition:
    hash.sha256(0, filesize) == "57478a0f3dcf4df1c96dbb3cd9aa3b255814bd3a4185bf90ba768eb28b471797"
}
```

### Sample 11: `c9698c118c2ba58f`

| Field | Value |
|---|---|
| SHA-256 | `c9698c118c2ba58fb2c7944354687333bd4f0d58ce5b6710920cdfa682bc9944` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:31:49` |
| Reporter | `iamaachum` |
| Tags | `178-105-46-149, exe, signed, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4618b1cf240c99032b4f7ca2d4af724f` |
| SHA-1 | `7913d064a91596b01112372ed372053a592b8b39` |
| SHA-256 | `c9698c118c2ba58fb2c7944354687333bd4f0d58ce5b6710920cdfa682bc9944` |
| SHA3-384 | `9a4b4c3f0f9f7e71d5bac54c210cddcc8b19015717d6bc7fae1a48e2ffb41838396a49c6baf1482ce3d519f90fb18aff` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1DEF5AE27ADB142B6C899A73586B61150B530B808D73233E76E50FFB43E707C9AE75B84` |
| SSDEEP | `49152:9LlbIJU57UuJ6TGk6ahvJK8bksXuDMKDxvxx4aBGcctAxG:B7kPvaBlcJ` |
| ICON-DHASH | `b29269e8ece4e8b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_c9698c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9698c118c2ba58fb2c7944354687333bd4f0d58ce5b6710920cdfa682bc9944"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:31:49"
  condition:
    hash.sha256(0, filesize) == "c9698c118c2ba58fb2c7944354687333bd4f0d58ce5b6710920cdfa682bc9944"
}
```

### Sample 12: `514fa7786356f49a`

| Field | Value |
|---|---|
| SHA-256 | `514fa7786356f49ad0e1164fec6fcfb3c2759db9c069beac2f89baa804f7d5fe` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:30:56` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d944ff591ebcff069f17e5e57180a6f` |
| SHA-1 | `c5f1ea4f7fb4e9b3dd5a3257f051110edcd613d0` |
| SHA-256 | `514fa7786356f49ad0e1164fec6fcfb3c2759db9c069beac2f89baa804f7d5fe` |
| SHA3-384 | `8747358d8f4b77a57b86f215d97c7132cdb9348dd9ef22e260bfaf21c022db5329ae7a18f59363f3815b061561e95706` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T12EB55A077E8042A5D49AE735C9B64251B230BC4CC73537D72F91AAB42FB27D2AA76F10` |
| SSDEEP | `24576:3tAlyd3NmedAli1zuVrMxEgIvfh1t7OdZdExN8d2RckGplqaUYj3Bah:ilyZNXdA0OMeZ1t2ZdET8ntY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_514fa778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "514fa7786356f49ad0e1164fec6fcfb3c2759db9c069beac2f89baa804f7d5fe"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:30:56"
  condition:
    hash.sha256(0, filesize) == "514fa7786356f49ad0e1164fec6fcfb3c2759db9c069beac2f89baa804f7d5fe"
}
```

### Sample 13: `f4a8e4307944c6de`

| Field | Value |
|---|---|
| SHA-256 | `f4a8e4307944c6decec264820f699e4e4adee02fc71da530ad862dee959528cb` |
| Family label | `unknown` |
| File name | `LauncherV33281.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:29:30` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe1df8e405bcd3672f3cafbb667831c0` |
| SHA-1 | `e87636567b277c51b7c4fb6e5f71e4f1b8f8997a` |
| SHA-256 | `f4a8e4307944c6decec264820f699e4e4adee02fc71da530ad862dee959528cb` |
| SHA3-384 | `53f09d18757a07fb7a80d51525d579e41b48c99d262f9868d89795ac28e90a4f7efd5018618054902ee0c5b4046e0a30` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T198F633A64256D15ADDB1503A6BD0E9B99B11BB448C1D030D2FE33ABDF2E52B2BFC105C` |
| SSDEEP | `393216:cI0EHldZw7OgWtsKvdJhYZDr7fQCx7VR3QSMMaVTH0D2:cwSOptsKvdUz1xJxjMMEH` |
| ICON-DHASH | `10d2e2e6dcecc6e2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_f4a8e430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4a8e4307944c6decec264820f699e4e4adee02fc71da530ad862dee959528cb"
    family = "unknown"
    file_name = "LauncherV33281.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:29:30"
  condition:
    hash.sha256(0, filesize) == "f4a8e4307944c6decec264820f699e4e4adee02fc71da530ad862dee959528cb"
}
```

### Sample 14: `80cd87cbf731d14b`

| Field | Value |
|---|---|
| SHA-256 | `80cd87cbf731d14baa0698a22a0ebf8db7b305a740d0015d985e94b6b197a2f3` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-08-15 00:28:59` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cae55328112416dd21369d80194f8b0` |
| SHA-1 | `155ac54f910dca9a40165289b79410074c401380` |
| SHA-256 | `80cd87cbf731d14baa0698a22a0ebf8db7b305a740d0015d985e94b6b197a2f3` |
| SHA3-384 | `23c0992014bd3168ef2c0bc56fb9d39ba73f8ac641d2993c5490632c569fa1e1f55abda35a80a74e0eae2853153281a6` |
| TLSH | `T1F2F633A64256D15ADDB0503A6BD0E9B99A11BB444C2D030D2FE73ABDF3E52B2BFC105C` |
| SSDEEP | `393216:gI0EHldZw7OgWtsKvdJhYZDr7fQCx7VR3QSMMaVTH0D2:gwSOptsKvdUz1xJxjMMEH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_80cd87cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80cd87cbf731d14baa0698a22a0ebf8db7b305a740d0015d985e94b6b197a2f3"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-15 00:28:59"
  condition:
    hash.sha256(0, filesize) == "80cd87cbf731d14baa0698a22a0ebf8db7b305a740d0015d985e94b6b197a2f3"
}
```

### Sample 15: `7e52031a2ef38882`

| Field | Value |
|---|---|
| SHA-256 | `7e52031a2ef388824fd6e39f25b626b09be13e33a79d291a4790affdb9b93593` |
| Family label | `unknown` |
| File name | `FLStudio2025_v256_Win.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:28:10` |
| Reporter | `iamaachum` |
| Tags | `cloud-flare-authenticator-link, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ece5582a6cca57b558b5a98290b3699` |
| SHA-1 | `76b7d9208456ddfd5a59c99826af2217c3f86168` |
| SHA-256 | `7e52031a2ef388824fd6e39f25b626b09be13e33a79d291a4790affdb9b93593` |
| SHA3-384 | `4be4ac56602d93b8f1eab7e617f1d89b17157629504107312fc47c387c9713302837aad83b76a0f5e417b5ccb1c98876` |
| IMPHASH | `7d2ba17446ccc847880dd090d875a2bd` |
| TLSH | `T199551B1200785A61BF4165F9A5870373E7530031DAA0FB52EFAF95E92F7275B82DC2E8` |
| SSDEEP | `24576:VKMKVf00arQv8wivKvUQliOgzmNqPuYH4zvutc3rHlVg8HjuWssBFk8uCxCfN+4j:VK5VfHa2KvKd8VzmNqWYH4zvutc3rHl8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_7e52031a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e52031a2ef388824fd6e39f25b626b09be13e33a79d291a4790affdb9b93593"
    family = "unknown"
    file_name = "FLStudio2025_v256_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:28:10"
  condition:
    hash.sha256(0, filesize) == "7e52031a2ef388824fd6e39f25b626b09be13e33a79d291a4790affdb9b93593"
}
```

### Sample 16: `6702d4f508ebf248`

| Field | Value |
|---|---|
| SHA-256 | `6702d4f508ebf248a56bb2d14b1afdc8557398b3b94c25a6d23eb61533647373` |
| Family label | `unknown` |
| File name | `atom.dll` |
| File type | `exe` |
| First seen | `2026-08-15 00:25:56` |
| Reporter | `iamaachum` |
| Tags | `2-26-126-50, BlakcSeeStealer, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc2f88f368a32c8ba7257bd54a830068` |
| SHA-1 | `c81953bb0d5bf418cc1b84ed0dd0027ab448ee0f` |
| SHA-256 | `6702d4f508ebf248a56bb2d14b1afdc8557398b3b94c25a6d23eb61533647373` |
| SHA3-384 | `58635d153edf8b7f713fd16ffb9b9f630006560336648d95784802b90940d052d024194c8f47602db8cfb1d677756dd4` |
| IMPHASH | `b1ee8cad62aefbc15bc55581d96594ac` |
| TLSH | `T18F26BF8573C86ADDC422DD7B5714F232C1E3A9238EB7D0C65E96C70A4EB6A524F39B40` |
| SSDEEP | `98304:1PaVCsru7TzKpQFVNkGk9DqIXHhR+MsPlJBjom/Pyb4hTsIYxogb/f5+xjzJ2QIO:1SVCw5qVNkGQnnDsP9jomHk4ldgjf5+4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_6702d4f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6702d4f508ebf248a56bb2d14b1afdc8557398b3b94c25a6d23eb61533647373"
    family = "unknown"
    file_name = "atom.dll"
    file_type = "exe"
    first_seen = "2026-08-15 00:25:56"
  condition:
    hash.sha256(0, filesize) == "6702d4f508ebf248a56bb2d14b1afdc8557398b3b94c25a6d23eb61533647373"
}
```

### Sample 17: `ad1f1c29707bba2a`

| Field | Value |
|---|---|
| SHA-256 | `ad1f1c29707bba2a41e9d964abb63ff0dc764ea98c3e2a1e38a39dd2c7bcfd6b` |
| Family label | `unknown` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:23:17` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, windowsof-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e973fd7c15c435631fc18e1df82592a` |
| SHA-1 | `93273d32065f099ae72fbf818e70fda2233acbc1` |
| SHA-256 | `ad1f1c29707bba2a41e9d964abb63ff0dc764ea98c3e2a1e38a39dd2c7bcfd6b` |
| SHA3-384 | `4dd9ac73229ca89a726a7bb813b46bc852af50f87061d77b89533fd65b2316c39fd8f0001f7f6b74cd4963e355d0a524` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T167C55A0B2C904665CA53D339A4B312267B74BD58CB3573D72D91AB702F71BC26EB9B08` |
| SSDEEP | `24576:ltptFI7FtX9GKap5nG/Ua6azwREHzZToS3VDTBEwhLUsaKOr:r7FIpttGKapHa6akuztoS3VnXoj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_ad1f1c29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad1f1c29707bba2a41e9d964abb63ff0dc764ea98c3e2a1e38a39dd2c7bcfd6b"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:23:17"
  condition:
    hash.sha256(0, filesize) == "ad1f1c29707bba2a41e9d964abb63ff0dc764ea98c3e2a1e38a39dd2c7bcfd6b"
}
```

### Sample 18: `b60ad1eee8bc9dcd`

| Field | Value |
|---|---|
| SHA-256 | `b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c` |
| Family label | `unknown` |
| File name | `b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c.bin` |
| File type | `exe` |
| First seen | `2026-08-15 00:23:17` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbf695c86f8e0ec38f0630b33766c655` |
| SHA-1 | `a87d71802a427739e07f1cbb4c289491eb3161e4` |
| SHA-256 | `b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c` |
| SHA3-384 | `46c41095085e24ed76634ba597302a8fe67717e1aeaf27d51a30c9677a61a2d2867aa2bb9ffb0e93acbcee54222e5ac9` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T16AF59D077E5452A8D4CADB35C8B22691B624FC0D973537E33EA0AB706F317D6A976B00` |
| SSDEEP | `49152:fk2nM0Gj9gvIcRzm77htL293kjjN8rd0W:g9j97j2931b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_b60ad1ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c"
    family = "unknown"
    file_name = "b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c.bin"
    file_type = "exe"
    first_seen = "2026-08-15 00:23:17"
  condition:
    hash.sha256(0, filesize) == "b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c"
}
```

### Sample 19: `5cc44ec9af3b258d`

| Field | Value |
|---|---|
| SHA-256 | `5cc44ec9af3b258dc4cd4fddccfa03550e8f5d3aa57fe78eb9c0805ed0850182` |
| Family label | `unknown` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:21:55` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5fb52cb4836455493489879979cf724` |
| SHA-1 | `35ac62eefcad505cd25e97b9aff3c147a608c27e` |
| SHA-256 | `5cc44ec9af3b258dc4cd4fddccfa03550e8f5d3aa57fe78eb9c0805ed0850182` |
| SHA3-384 | `1b39ae8128ee7e96c885271bc0b21cd087dccedc0a0378d6f81ec1378e37e90cf94ab517666802a002e7f2ba51ae7fe2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A016AD077D9140E5C4EAAB31C5B782627A61BC0C8B7933DB2E90AA782F723D25D75F44` |
| SSDEEP | `98304:oTTKaw3lqwTABtbFxKmKPqVoZsEIi+nZNd+ZbRA:o3Kaw3l0HiMZNdm2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_5cc44ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cc44ec9af3b258dc4cd4fddccfa03550e8f5d3aa57fe78eb9c0805ed0850182"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:21:55"
  condition:
    hash.sha256(0, filesize) == "5cc44ec9af3b258dc4cd4fddccfa03550e8f5d3aa57fe78eb9c0805ed0850182"
}
```

### Sample 20: `2ceeac4dd38579e8`

| Field | Value |
|---|---|
| SHA-256 | `2ceeac4dd38579e87936343e2819492ac88dd27d489aa72ef5c622e772f9bf0c` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-15 00:12:14` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3797091b6196e1b90f824d70e54a1c7` |
| SHA-1 | `64964c760b8e54c6074606328da6ff51462a53c8` |
| SHA-256 | `2ceeac4dd38579e87936343e2819492ac88dd27d489aa72ef5c622e772f9bf0c` |
| SHA3-384 | `932955bdbacec3641fa01e9d4f104060ceb5bccfb0f286c6c00b5b5fef34133ccbc50ecdf3c0ac2e17e584d8245e8fde` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T11BF5AD07BE9042A5C49AE736C9726691B730BC0CC73127E72F50A6B42F667C2AD76F50` |
| SSDEEP | `49152:GGKBMi8ZJk6Cu0pJxW6fE9QXw1u+69b2tukeO5qk+TbH:/JEuUxTEQAtweus5qp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_2ceeac4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ceeac4dd38579e87936343e2819492ac88dd27d489aa72ef5c622e772f9bf0c"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:12:14"
  condition:
    hash.sha256(0, filesize) == "2ceeac4dd38579e87936343e2819492ac88dd27d489aa72ef5c622e772f9bf0c"
}
```

### Sample 21: `709716d13a356e2e`

| Field | Value |
|---|---|
| SHA-256 | `709716d13a356e2ef12dedd3313eeac002dcab955c50406bd2dfe38fab5a1c1a` |
| Family label | `Mirai` |
| File name | `5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d.elf` |
| File type | `elf` |
| First seen | `2026-08-15 00:05:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a49a436fc54e8b99f55627f20ae7c5c7` |
| SHA-1 | `f676db41a05f8a799152b018332bcb40e8f9b5af` |
| SHA-256 | `709716d13a356e2ef12dedd3313eeac002dcab955c50406bd2dfe38fab5a1c1a` |
| SHA3-384 | `a5fa1ed71418bad880b5db377047be92f85c3a5adca098c0d77eab6d157aab7dd3f81ecdf02bf23eca35115b0d659254` |
| TLSH | `T120B31891BC829622C6C2567BFB5E418E371753A8D3EE32039D196F20738B95F0E77642` |
| TELFHASH | `t104f07d35dfa81d495bc78224912b751a59c8b14a1a5d3512897c6e853921286b50cc0f` |
| SSDEEP | `3072:WyyoUtt250nfMfia1H5Ju3Emot5wjCDc:Wyev250nfMfFw3EmoseDc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_709716d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "709716d13a356e2ef12dedd3313eeac002dcab955c50406bd2dfe38fab5a1c1a"
    family = "Mirai"
    file_name = "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:05:49"
  condition:
    hash.sha256(0, filesize) == "709716d13a356e2ef12dedd3313eeac002dcab955c50406bd2dfe38fab5a1c1a"
}
```

### Sample 22: `df4888a7ef78e32e`

| Field | Value |
|---|---|
| SHA-256 | `df4888a7ef78e32e2819fe5af82369ecc85b681e5648837224fd44d413e267df` |
| Family label | `Mirai` |
| File name | `e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39.elf` |
| File type | `elf` |
| First seen | `2026-08-15 00:05:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39b8d54468b033042e11dc1401138171` |
| SHA-1 | `d484eb5bcf9d2221b17f159e7e758200b47f6003` |
| SHA-256 | `df4888a7ef78e32e2819fe5af82369ecc85b681e5648837224fd44d413e267df` |
| SHA3-384 | `ab77fdebea82aa0902a5a7635c721f11d69e5a2df4e3c6c4abaf4085d77b4b36292925f6c8fecc69559bcf3e48b68b37` |
| TLSH | `T125E3D60ABB210EFBE8ABDD3746E90B06358C641721A93F3A7A74D518F54B54F09E3874` |
| SSDEEP | `1536:lqxb9PxK0rkBXr3MYLtw0leFY/e3bBL0vjWmXOa4lcKJDhZbPe0BzRSt2d2ruKEj:laPxK0ijZLtnOz2K9hIKRTk6/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_df4888a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df4888a7ef78e32e2819fe5af82369ecc85b681e5648837224fd44d413e267df"
    family = "Mirai"
    file_name = "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:05:46"
  condition:
    hash.sha256(0, filesize) == "df4888a7ef78e32e2819fe5af82369ecc85b681e5648837224fd44d413e267df"
}
```

### Sample 23: `5fa395bbe688fbbd`

| Field | Value |
|---|---|
| SHA-256 | `5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d` |
| Family label | `Mirai` |
| File name | `5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d.elf` |
| File type | `elf` |
| First seen | `2026-08-15 00:04:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ce30a383bba6fa99bcc4aa465e59e37` |
| SHA-1 | `5748f3a6c4ceacf8b501940b710c6f82146ba25f` |
| SHA-256 | `5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d` |
| SHA3-384 | `550285f735d6afcc3bb74c4a4ad4eb9cbe5aa50993e249fb0099ff52f9dc9863014c657a3957298049eea9accabdf4b7` |
| TLSH | `T13A23F1A56FE035F647B0883EECA74C9A5A6A663CD7BE1A6035054B121E603437FB07C7` |
| SSDEEP | `768:kA95yRMau3pWo96+6dt8e1+DPCsler8xlVHbQUlRKwf8O7qYayhJ4gs3Uoz1:x95H7QoYHCeszCr8xzHbPKw56Vz1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_5fa395bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d"
    family = "Mirai"
    file_name = "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:04:33"
  condition:
    hash.sha256(0, filesize) == "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d"
}
```

### Sample 24: `e3b410b16785aa99`

| Field | Value |
|---|---|
| SHA-256 | `e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39` |
| Family label | `Mirai` |
| File name | `e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39.elf` |
| File type | `elf` |
| First seen | `2026-08-15 00:04:29` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9811965fd65f435a5c01e7d4411324f2` |
| SHA-1 | `bca017e93c8ace8095dd885fbceb525aa48d8194` |
| SHA-256 | `e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39` |
| SHA3-384 | `f829875b1f50de5cb9250965e1bdb463587f73d85937c99be034b0938077f90c9813d42ffc61a4cdeae5c35e852244d9` |
| TLSH | `T1E233F14E276038DADEA81DFEA14D578DC82BB0D0320B4F9826245C9DCF6989F76CD85C` |
| SSDEEP | `768:1guu+bGpQbMjK9dSdyDnViHVTx8SFZj07l5BlPfnCBAmPuKEKduaJwSsWf0:G+K9K9IdgViHVw77PKBAmZEG1ws0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_e3b410b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39"
    family = "Mirai"
    file_name = "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:04:29"
  condition:
    hash.sha256(0, filesize) == "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39"
}
```

### Sample 25: `c1466a7a1732dfdb`

| Field | Value |
|---|---|
| SHA-256 | `c1466a7a1732dfdba03457e094ee8dde9a9ebbaf856a7b66854e7ca8222cf976` |
| Family label | `Mirai` |
| File name | `376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97.elf` |
| File type | `elf` |
| First seen | `2026-08-14 23:55:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffafcbe2b413aa639cd4c9745b9c3abc` |
| SHA-1 | `7f1ef530a90ba2ed9b0b1820d9ac29e7a1f02ac0` |
| SHA-256 | `c1466a7a1732dfdba03457e094ee8dde9a9ebbaf856a7b66854e7ca8222cf976` |
| SHA3-384 | `bedd2cc7e81f301131a2f0ab59b7908b631f96c881aad61c99f29716bdc72e9a4281b91452b353cd7ff4bbb25ddd490a` |
| TLSH | `T1E1B31895F8829622C6C1667BFF1E418D371653A8E2EE32039D192F60778BC1F0E77652` |
| TELFHASH | `t1a4f07d65efb00ee92e93c578a45e311705aca1ba7718301558fe6f861693284741cc1f` |
| SSDEEP | `3072:BCXITBR9iRzbQYxyo7I5K8yQviuiC6gZH4A:BC6BR9iRXLMGl8yQviuV7ZHx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_c1466a7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1466a7a1732dfdba03457e094ee8dde9a9ebbaf856a7b66854e7ca8222cf976"
    family = "Mirai"
    file_name = "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97.elf"
    file_type = "elf"
    first_seen = "2026-08-14 23:55:42"
  condition:
    hash.sha256(0, filesize) == "c1466a7a1732dfdba03457e094ee8dde9a9ebbaf856a7b66854e7ca8222cf976"
}
```

### Sample 26: `376c342dc4261ca7`

| Field | Value |
|---|---|
| SHA-256 | `376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97` |
| Family label | `Mirai` |
| File name | `376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97.elf` |
| File type | `elf` |
| First seen | `2026-08-14 23:54:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b043705b528dbe6ebe5de02441aaf336` |
| SHA-1 | `6f5932a7c5540fbc8b78f8c764b6cbd47c683dbe` |
| SHA-256 | `376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97` |
| SHA3-384 | `4bcec8ec9e13531c194828e065382dc7cb35ff5109a86173f56c6bff2259ab748111528004a8c014d0875a09669b5d1b` |
| TLSH | `T13D23F131122C3C7083A5B9B27779C0A56E61163876E639339D7884CB25EF83536F978B` |
| SSDEEP | `768:g47MFsuQV53IhK4JKj9f7NgWYY2E36DATS+8Vb0z7/8CWsT6LVSgSuB1s3UozX:DgngdIRJKhpgWY5EqDATSBixuL8KazX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_376c342d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97"
    family = "Mirai"
    file_name = "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97.elf"
    file_type = "elf"
    first_seen = "2026-08-14 23:54:46"
  condition:
    hash.sha256(0, filesize) == "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97"
}
```

### Sample 27: `1182e436076f313f`

| Field | Value |
|---|---|
| SHA-256 | `1182e436076f313fb9f22b4cf27918570c50d0ec90fc10d6383a1e86448d68d5` |
| Family label | `unknown` |
| File name | `update.exe` |
| File type | `exe` |
| First seen | `2026-08-14 23:52:40` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, exe, KongTuke, MintsLoader, ModeloRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78cfe8bfbdad19f3afb54cd12d949db4` |
| SHA-1 | `b55f349e8cd15c07158207942b29d7138ef9c7e0` |
| SHA-256 | `1182e436076f313fb9f22b4cf27918570c50d0ec90fc10d6383a1e86448d68d5` |
| SHA3-384 | `291a0cc299827f6e65657577aea7b7e0a1e8e519b716f2c67eb36796ae3f3c7ef6fada0961ed41546c14ad933074be46` |
| IMPHASH | `ce564ba57e1cf5fb4dfdabcd24a1029e` |
| TLSH | `T1CF96F119736B29BAD121C83CC39A5E32D566390A9B71F05F4E0DC7610FB2523ADBBB11` |
| SSDEEP | `98304:YffuyMKpOyBXiASKFIGNI9JUPt2pCSVzVpuuZed9m3vdomOdEOOqx5qLVCulJDfw:Y3uyHb9IjUP8BpXu4/dzkqB35Uu6nt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_1182e436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1182e436076f313fb9f22b4cf27918570c50d0ec90fc10d6383a1e86448d68d5"
    family = "unknown"
    file_name = "update.exe"
    file_type = "exe"
    first_seen = "2026-08-14 23:52:40"
  condition:
    hash.sha256(0, filesize) == "1182e436076f313fb9f22b4cf27918570c50d0ec90fc10d6383a1e86448d68d5"
}
```

### Sample 28: `5316c1faefa33328`

| Field | Value |
|---|---|
| SHA-256 | `5316c1faefa33328e593d3cf4d54d6e25d7243862d65a67189f76d8b38a682ea` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 23:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed659ff4e9c2f5dca9866645cc7e8b50` |
| SHA-1 | `5808b595afc8bd757d53cb4f097fdc7e5608eb47` |
| SHA-256 | `5316c1faefa33328e593d3cf4d54d6e25d7243862d65a67189f76d8b38a682ea` |
| SHA3-384 | `ee62b7ba506160d3b05e48b40e50187585e06a30744f253b003a42cfa4f682b6990658dee096573f5927bcc289c2ba0e` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T170E63348DAD051DEEAB3953CEDE1216BE12AB4B64731C8EB13AC4671BD432E08C75727` |
| SSDEEP | `393216:CPh3HcnT27Tm0mafunmjzWedkYXMCHWUjlcuI3/PGTAI:6p8y7Tm0mqunmzkYXMb8SH/O7` |
| ICON-DHASH | `9adcf8f8dcf8e044` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_5316c1fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5316c1faefa33328e593d3cf4d54d6e25d7243862d65a67189f76d8b38a682ea"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 23:52:30"
  condition:
    hash.sha256(0, filesize) == "5316c1faefa33328e593d3cf4d54d6e25d7243862d65a67189f76d8b38a682ea"
}
```

### Sample 29: `cce7a3a488bbc717`

| Field | Value |
|---|---|
| SHA-256 | `cce7a3a488bbc717325a24528c733b820181feeda1a6c168f297c4a090aa3cb1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-14 23:39:34` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, PMIX0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2ea952de8b1bb2afc5a2be3a268a433` |
| SHA-1 | `63a9e6a56ce653494116948cb043fd275b5ee5b5` |
| SHA-256 | `cce7a3a488bbc717325a24528c733b820181feeda1a6c168f297c4a090aa3cb1` |
| SHA3-384 | `db6ef61dcbce1939eb5e2b23f1b71978986fe1d3faea84e15ddf4b2b528ca2f6502a0f4f526be3e92a81bf0a06770293` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T172E59D073E8442A8D496D73A86B36612B670BC0CC73573E72FA462742F767C1A976F18` |
| SSDEEP | `49152:u4rBwXGJ7bQl91PHBBHgOze0uHvDmMokUe9g2/X5cI:EhNzzeTviMote7/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_cce7a3a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cce7a3a488bbc717325a24528c733b820181feeda1a6c168f297c4a090aa3cb1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 23:39:34"
  condition:
    hash.sha256(0, filesize) == "cce7a3a488bbc717325a24528c733b820181feeda1a6c168f297c4a090aa3cb1"
}
```

### Sample 30: `59d42ff1cad50cd8`

| Field | Value |
|---|---|
| SHA-256 | `59d42ff1cad50cd84342e6ce6beb2896e63d36971b83bc42817bb227db04260f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-14 23:26:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d5a6ee922591d3cee3cf461bd03b915` |
| SHA-1 | `7f85fedcc2cb02206b4b35340014685a43997013` |
| SHA-256 | `59d42ff1cad50cd84342e6ce6beb2896e63d36971b83bc42817bb227db04260f` |
| SHA3-384 | `2f12de7a1363cc20d1abdd0aee455b81a7e9004c18ff9103c2a0a820d75f68aa8e05f826ca8d277f831d733c2718c394` |
| TLSH | `T112C28D956A967C44BEC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:S8vCB+25j6es8Rwv9FYpMSUpi+20qUpi+20YQX:S8l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_59d42ff1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d42ff1cad50cd84342e6ce6beb2896e63d36971b83bc42817bb227db04260f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 23:26:18"
  condition:
    hash.sha256(0, filesize) == "59d42ff1cad50cd84342e6ce6beb2896e63d36971b83bc42817bb227db04260f"
}
```

### Sample 31: `7d700aaf9805bc27`

| Field | Value |
|---|---|
| SHA-256 | `7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f` |
| Family label | `Mirai` |
| File name | `7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f.elf` |
| File type | `elf` |
| First seen | `2026-08-14 22:57:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc3fa0968adfd76392347626ccb6db54` |
| SHA-1 | `d501dd7d248f09ff7705c6f03d2f9a99811cc224` |
| SHA-256 | `7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f` |
| SHA3-384 | `b8fbd9ed588a28c0376d5d4dd825e2d8ccf467d8f931d0a0d1dfffc8d8fe44e3445867501172aaa40acecd57f58b167b` |
| TLSH | `T1E1D4D70B6E328F7DF67487314BF74A249BAD23D623E1C581D1ADD1151F2028E592FBA8` |
| TELFHASH | `t1afb14799297813e4ab546d8c46dcff32cca228ef2a561c33de50e85ed71ba835e10c1c` |
| SSDEEP | `6144:06RpD0VEoWaNOSRM2L+6xxPaJB7Y5HJWz4LV8RoB/aRsLjIPK1tCSYbyCXtsjh7v:ZRi+CO956xD3CX6cbMNpqnpbA3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_7d700aaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f"
    family = "Mirai"
    file_name = "7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f.elf"
    file_type = "elf"
    first_seen = "2026-08-14 22:57:08"
  condition:
    hash.sha256(0, filesize) == "7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f"
}
```

### Sample 32: `2b5994f3a89f4efb`

| Field | Value |
|---|---|
| SHA-256 | `2b5994f3a89f4efb1fc1459059b0b74c4935cb587981caeaae14598582058368` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 22:52:50` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `762792354f7114f7de7420b0c2d77912` |
| SHA-1 | `de1efd1c7a44c5fd268cba68dd9ad9fbc4587536` |
| SHA-256 | `2b5994f3a89f4efb1fc1459059b0b74c4935cb587981caeaae14598582058368` |
| SHA3-384 | `c86a8ed50c5282814239bf3a79da8c1ed47627179e805dea074973013ee81c3b6a064243d9be93271132c5ddce343a2b` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T174E633485AC0B2D7EEB3847CEAF12995E56EBCB80B31C9CB83F467915E571D48C39112` |
| SSDEEP | `393216:oCp40fu9xmD+IgG7ZI0zhFVXMCHWUjucuI3/PGTAI:oq4YD/3xXMb8DH/O7` |
| ICON-DHASH | `d4f0f0e8e8e07130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_2b5994f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b5994f3a89f4efb1fc1459059b0b74c4935cb587981caeaae14598582058368"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 22:52:50"
  condition:
    hash.sha256(0, filesize) == "2b5994f3a89f4efb1fc1459059b0b74c4935cb587981caeaae14598582058368"
}
```

### Sample 33: `ce2d0bbd100e613b`

| Field | Value |
|---|---|
| SHA-256 | `ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112` |
| Family label | `Prometei` |
| File name | `ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112` |
| File type | `elf` |
| First seen | `2026-08-14 22:51:38` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58766aeb082aa03cc0cf9484fa6b0598` |
| SHA-1 | `154685ba5f05a49245582895345f4c440fc9eff8` |
| SHA-256 | `ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112` |
| SHA3-384 | `4ee1b8b849ee72bf0d697ce89fb47ae2ddd87f6b53d8eff9b818a42f5d0dbe5b1ad194f25c4ade97c2d4ed1f0f26fe5c` |
| TLSH | `T144A423B4F9219E8F6DD769F91B24831DE182C172589D4C2313AE94A34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdA:Fs6pyCC/Ya2hpi6T6N4i` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_033_ce2d0bbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112"
    family = "Prometei"
    file_name = "ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112"
    file_type = "elf"
    first_seen = "2026-08-14 22:51:38"
  condition:
    hash.sha256(0, filesize) == "ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112"
}
```

### Sample 34: `d44ff00fe9552510`

| Field | Value |
|---|---|
| SHA-256 | `d44ff00fe9552510aefbf13c4b986dc094b5aefcd099fd3d7ad6dc816968a50b` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Variant.Packed.Themida.21.63687778` |
| File type | `exe` |
| First seen | `2026-08-14 22:47:03` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45899f8f753e57ded07eb20ca57be0f1` |
| SHA-1 | `c714a73211957aa0c71defa91d4d6beca8e4abb8` |
| SHA-256 | `d44ff00fe9552510aefbf13c4b986dc094b5aefcd099fd3d7ad6dc816968a50b` |
| SHA3-384 | `24bbaad6bec834566adacf5bd0390166a2e5ae3abf1713469b33494a82c8c8896a4470905b56429b1726e496c1c2af8d` |
| IMPHASH | `35a81d16af9f2ba6d515f11152d0364b` |
| TLSH | `T1AB9633572D9B6DEBC7B866B86C8E06336308C78D08F487DEE5A5480654335722EB42DF` |
| SSDEEP | `196608:S+mu1iWy7DOesa7jxatMRlrIM31bxKyb0R5+x9CT1pf3:3m4YDO/a7jYelXldq+81p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_d44ff00f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d44ff00fe9552510aefbf13c4b986dc094b5aefcd099fd3d7ad6dc816968a50b"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Packed.Themida.21.63687778"
    file_type = "exe"
    first_seen = "2026-08-14 22:47:03"
  condition:
    hash.sha256(0, filesize) == "d44ff00fe9552510aefbf13c4b986dc094b5aefcd099fd3d7ad6dc816968a50b"
}
```

### Sample 35: `5869e740ee9d36f6`

| Field | Value |
|---|---|
| SHA-256 | `5869e740ee9d36f62ee9e6e01b4deded4970043d6a6cdd792d0beb383b62c842` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Variant.Midie.185781.47871582` |
| File type | `exe` |
| First seen | `2026-08-14 22:47:01` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e729ad151614c96d872320b40e2f2ad2` |
| SHA-1 | `4eec8596628db00cac1983789a55ee8c540a2ddd` |
| SHA-256 | `5869e740ee9d36f62ee9e6e01b4deded4970043d6a6cdd792d0beb383b62c842` |
| SHA3-384 | `fad451a7303cb246d47bc37f9f3db61a95c5149fb0f8615d6ad5884c25b266221c8f1790354b9c1bdb7d320895e277c6` |
| IMPHASH | `833ade2e2033609f215c8fc001139f6e` |
| TLSH | `T11F26332E84017B82E9E1887E7C675401CD25BE614BA73261377FBE90B65AC4D0F34BAD` |
| SSDEEP | `98304:KBKKYkq9JWXtqLrRSRlCp6JPCexX6BzLq0+AaDPHsEqi+Ww4:PrUqec5e1h0+DD/bqi+V4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_5869e740
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5869e740ee9d36f62ee9e6e01b4deded4970043d6a6cdd792d0beb383b62c842"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Midie.185781.47871582"
    file_type = "exe"
    first_seen = "2026-08-14 22:47:01"
  condition:
    hash.sha256(0, filesize) == "5869e740ee9d36f62ee9e6e01b4deded4970043d6a6cdd792d0beb383b62c842"
}
```

### Sample 36: `ed6a55a28e225202`

| Field | Value |
|---|---|
| SHA-256 | `ed6a55a28e22520219c90adeb569c114ab8f01f1e1f2674e06615fe046e7a291` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 21:52:52` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9e1f05c2fef02d320bc2b6aa901f4fd` |
| SHA-1 | `f24465bbae171b3b2dadc5403cac20e6a22bb7b3` |
| SHA-256 | `ed6a55a28e22520219c90adeb569c114ab8f01f1e1f2674e06615fe046e7a291` |
| SHA3-384 | `65d061fcfa7b02d2bc5e2960b12d700fa182f9fdc1db13eff384add38600b71d70db3fa0575dc930c7399c091189952c` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T128E6334C66E102FDFCB3D038EB9202A5E465F43A5376C9CB87584376AF532F04939A66` |
| SSDEEP | `393216:mIQVvip4baIHMevP2Qa3jHEEXMCHWUjscuI3/PGTAI:mP64beevjaTHEEXMb85H/O7` |
| ICON-DHASH | `f0f1d4d8c8e4f130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_ed6a55a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed6a55a28e22520219c90adeb569c114ab8f01f1e1f2674e06615fe046e7a291"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 21:52:52"
  condition:
    hash.sha256(0, filesize) == "ed6a55a28e22520219c90adeb569c114ab8f01f1e1f2674e06615fe046e7a291"
}
```

### Sample 37: `48a2b07e5135769f`

| Field | Value |
|---|---|
| SHA-256 | `48a2b07e5135769fd31f8fa6ab2ba75ab1e7b3f50b0378ca5eb0f4cd2cd2dc20` |
| Family label | `unknown` |
| File name | `vmvshgsozcauxmsezzpi.exe` |
| File type | `exe` |
| First seen | `2026-08-14 21:48:56` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae07c8b68fcc25fe927fc1b66bf519dd` |
| SHA-1 | `5baa88fd843cf52895396fdaf07dc26cd14267ec` |
| SHA-256 | `48a2b07e5135769fd31f8fa6ab2ba75ab1e7b3f50b0378ca5eb0f4cd2cd2dc20` |
| SHA3-384 | `49da09887c21a68e3f5099e9a3d9adb12f911521a4efd91dd84b6497471342c01294fc03ad5ad7da7058403a40d9c527` |
| IMPHASH | `d3d692ca53ebf794ada25d19a8f1d07d` |
| TLSH | `T1C416BF62BB41C071F9C201B964BE9F7A497DAE204775C0D397D43E6A88311D32B3A79B` |
| SSDEEP | `98304:7JeV/ztZBe91oiImuUiK9N9EGQKF9lSHbr7a7:1S/hwkmg4EpbrO7` |
| ICON-DHASH | `d4e6e6d3f2bcc870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_48a2b07e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48a2b07e5135769fd31f8fa6ab2ba75ab1e7b3f50b0378ca5eb0f4cd2cd2dc20"
    family = "unknown"
    file_name = "vmvshgsozcauxmsezzpi.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:48:56"
  condition:
    hash.sha256(0, filesize) == "48a2b07e5135769fd31f8fa6ab2ba75ab1e7b3f50b0378ca5eb0f4cd2cd2dc20"
}
```

### Sample 38: `aafaddd58c513931`

| Field | Value |
|---|---|
| SHA-256 | `aafaddd58c513931655be4a52b11317283b500ef27608a83af45d4e625568d20` |
| Family label | `ValleyRAT` |
| File name | `appinst_up001.exe` |
| File type | `exe` |
| First seen | `2026-08-14 21:33:36` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `079d47dd089638b90a5741175e15760f` |
| SHA-1 | `4068c64946bc4bafa70fba0bef12fd1568d62441` |
| SHA-256 | `aafaddd58c513931655be4a52b11317283b500ef27608a83af45d4e625568d20` |
| SHA3-384 | `9560f18561a584f57aa4ce960c7b88cfdbfd37f8976078276175af494de8886382736d2cdbd3dca1902597c0e31588cf` |
| IMPHASH | `380560563ebacca1589d8d38ac610187` |
| TLSH | `T1C587F84ABB41CDD9E136923894AB5F01E331E97186B1976333B02729CFDB38C8F66558` |
| SSDEEP | `196608:AFnmfRW0ATZPh7c2Qp3BqtiEPFNPyDhC81eHIJ:4SRgXQhDhf1u0` |
| ICON-DHASH | `c4e0b0a4cc74626a` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_038_aafaddd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aafaddd58c513931655be4a52b11317283b500ef27608a83af45d4e625568d20"
    family = "ValleyRAT"
    file_name = "appinst_up001.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:33:36"
  condition:
    hash.sha256(0, filesize) == "aafaddd58c513931655be4a52b11317283b500ef27608a83af45d4e625568d20"
}
```

### Sample 39: `ccd2629ecdbaefa6`

| Field | Value |
|---|---|
| SHA-256 | `ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de` |
| Family label | `unknown` |
| File name | `ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de.exe` |
| File type | `exe` |
| First seen | `2026-08-14 21:29:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b033f2d8467f39cc6f3d4687f41aeea9` |
| SHA-1 | `866eff8b335bc4d4140855e9d574c5b2b95b7d51` |
| SHA-256 | `ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de` |
| SHA3-384 | `8b7d52dd5d1e3a09764afb5da09a36c6a37772efba5b7bc8aa0904498ccd6c91b0f755a1ef1e2e226e133ce0f27afb4e` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T1CED5239AA8F218B4C077C772DF93E06FB1697B824B644E5BB3CD29118E526442C3B375` |
| SSDEEP | `49152:oDdIuZcrjYNcyu8Ezgrm0INdXyhdj7lqbRTkl7lytZSGrhXrIGDoDN:oLZcHnyDEzmm0IbChdnl2GlytIcrL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_ccd2629e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de"
    family = "unknown"
    file_name = "ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:29:46"
  condition:
    hash.sha256(0, filesize) == "ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de"
}
```

### Sample 40: `88bf710192a943e7`

| Field | Value |
|---|---|
| SHA-256 | `88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303` |
| Family label | `unknown` |
| File name | `88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303.exe` |
| File type | `exe` |
| First seen | `2026-08-14 21:29:40` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7749e5c411d81ee5449d69ace50e144c` |
| SHA-1 | `fc37f8abf2dd65097db431b33d73977589ee7834` |
| SHA-256 | `88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303` |
| SHA3-384 | `25f47bb2fd3f452c8b07e54232b8cd318e5176b31971e34690d086638e629fe2d39c9069c1ec2dfa989ea76a288afaa4` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T163D5238DF8D27979E036C7B747E7A0AEB12A77448B708D8F3AC85B509D116182C7B325` |
| SSDEEP | `49152:umAGKSnfBdcaJmkNBul+EZH14MJwT4EchKG3UY48+oGvnZMyo8X6uA4joKNU:WTMJ3JmwBEH14e84EKz8o6n24ewoK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_88bf7101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303"
    family = "unknown"
    file_name = "88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:29:40"
  condition:
    hash.sha256(0, filesize) == "88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303"
}
```

### Sample 41: `3780482094b9322d`

| Field | Value |
|---|---|
| SHA-256 | `3780482094b9322d8869c7c52966a49e7f285c0016525ffffa6d5458231c271f` |
| Family label | `unknown` |
| File name | `vmvshgsozcauxmsezzpi.exe` |
| File type | `exe` |
| First seen | `2026-08-14 21:14:22` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6b33502a514fdad2c1b2605a1967865` |
| SHA-1 | `11ba3e2da68268b660f6f60beac87f82e170a86a` |
| SHA-256 | `3780482094b9322d8869c7c52966a49e7f285c0016525ffffa6d5458231c271f` |
| SHA3-384 | `0603db00e7d11f98463a7fb9c19c1c14ce0a63ac16f1bfd965743da48137076ffcc03504f173d61d9be65a31aef88e8d` |
| IMPHASH | `d3d692ca53ebf794ada25d19a8f1d07d` |
| TLSH | `T10016BF62BB41C071F9C201B964BE9F7A497DAE204775C0D397D43E6A88311D32B3A79B` |
| SSDEEP | `98304:7JeV/ztZBe91oiImuUiK9N9EGQKF9lSHbr7az:1S/hwkmg4EpbrOz` |
| ICON-DHASH | `d4e6e6d3f2bcc870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_37804820
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3780482094b9322d8869c7c52966a49e7f285c0016525ffffa6d5458231c271f"
    family = "unknown"
    file_name = "vmvshgsozcauxmsezzpi.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:14:22"
  condition:
    hash.sha256(0, filesize) == "3780482094b9322d8869c7c52966a49e7f285c0016525ffffa6d5458231c271f"
}
```

### Sample 42: `d2d397702d12849d`

| Field | Value |
|---|---|
| SHA-256 | `d2d397702d12849d4db154c4470dea306cb88d9c95755a37aafde09e61769781` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-08-14 20:58:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5605cfe1e14471d702bd51ff5f3c263` |
| SHA-1 | `0e4e1ecbe77c8d042f3293d97c711866d2d66118` |
| SHA-256 | `d2d397702d12849d4db154c4470dea306cb88d9c95755a37aafde09e61769781` |
| SHA3-384 | `a77c71b70929ce3fa27d57539715602b0981b567e01d653345a3f57e32df0a3032331b909b35d6cf9612679ca73a21ee` |
| TLSH | `T172B34C02B31C0A57E1675DB03A3F27D193EEE9D061F4F688250EAB4992B5D361187ECD` |
| SSDEEP | `1536:ynriP+a8nfdL1WSRzuBPO7Ib2cv/1OoXSYJTGW1Vav2zEZQ3kf:8XVRdzu89HoXfJTGXWUf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_d2d39770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d397702d12849d4db154c4470dea306cb88d9c95755a37aafde09e61769781"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-08-14 20:58:41"
  condition:
    hash.sha256(0, filesize) == "d2d397702d12849d4db154c4470dea306cb88d9c95755a37aafde09e61769781"
}
```

### Sample 43: `9e3e3514cd791e9a`

| Field | Value |
|---|---|
| SHA-256 | `9e3e3514cd791e9aeef6e0d4274a46534213b4b30318c24d5bddc287738ca4b6` |
| Family label | `unknown` |
| File name | `my_sss.exe` |
| File type | `exe` |
| First seen | `2026-08-14 20:58:01` |
| Reporter | `James_inthe_box` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c626bc117bb70231a21a0738615cf42c` |
| SHA-1 | `4cc0c4b8d859d1bfb301d0bf3b66422bdff15fda` |
| SHA-256 | `9e3e3514cd791e9aeef6e0d4274a46534213b4b30318c24d5bddc287738ca4b6` |
| SHA3-384 | `09ebd12c7a5154678add9192e9921aed19d8cee16998d1cbb2db35e1f421c893bed0e982340e8363386c4c538f1f5500` |
| IMPHASH | `edc8ef44e1870aad7a3e58dab17f8e1b` |
| TLSH | `T188649D6A93A434F9D6EB40B2D4112A4483FAA4251331D7DB4F7485DA6F233D1DE3AEB0` |
| SSDEEP | `6144:x77TFdsCdmJVSIBbUDRw9wkJNtUOlltbSLHsA38bGgM:x77TFLmJVSIBbJVJnUAYlng` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_9e3e3514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e3e3514cd791e9aeef6e0d4274a46534213b4b30318c24d5bddc287738ca4b6"
    family = "unknown"
    file_name = "my_sss.exe"
    file_type = "exe"
    first_seen = "2026-08-14 20:58:01"
  condition:
    hash.sha256(0, filesize) == "9e3e3514cd791e9aeef6e0d4274a46534213b4b30318c24d5bddc287738ca4b6"
}
```

### Sample 44: `e156572994d3a6d9`

| Field | Value |
|---|---|
| SHA-256 | `e156572994d3a6d977ffed757b4ea6723b1e35d2c03db01dfe2f53f1d6d3b848` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-08-14 20:57:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a96e32d2c96d76e61def5b6431d10a44` |
| SHA-1 | `65f7c602993f72414de3ea2259f8a9ea878f6f8d` |
| SHA-256 | `e156572994d3a6d977ffed757b4ea6723b1e35d2c03db01dfe2f53f1d6d3b848` |
| SHA3-384 | `189250889effe6fd7856a0f489a1b0f5fcb06e07c5adbb429f21ad091a930f6596e78d678bab056d5435edca64ca1794` |
| TLSH | `T11523F127C16436C9DE66AE798A3BDA4417E335CE36A78EF184C5E7100383E511245EEE` |
| SSDEEP | `768:134CMIbeNefecn1b82TMhew/CbcNNlRSwMIIgzSTNcAV4Nn45w2aEIddvOUCk4ub:llycfeuBTMhF8cNIwbIrJfdO2had4u+w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_e1565729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e156572994d3a6d977ffed757b4ea6723b1e35d2c03db01dfe2f53f1d6d3b848"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-08-14 20:57:52"
  condition:
    hash.sha256(0, filesize) == "e156572994d3a6d977ffed757b4ea6723b1e35d2c03db01dfe2f53f1d6d3b848"
}
```

### Sample 45: `4840f24362fab800`

| Field | Value |
|---|---|
| SHA-256 | `4840f24362fab800677052f41e6075ea8378660a43621d7ab497268c36b322b4` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-14 20:57:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11502658112e2f2b95f5d3d89cffdc90` |
| SHA-1 | `f0d08742099558d4b350b9053e221fdae25613c6` |
| SHA-256 | `4840f24362fab800677052f41e6075ea8378660a43621d7ab497268c36b322b4` |
| SHA3-384 | `c8a94776a479044b9c3879681fc509fa3f33fe827b0b4efd2c2c721bd35cd6a9c4e5ced1896f5211a386cf14bcdaec6b` |
| TLSH | `T187235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A6ADD10971D` |
| SSDEEP | `768:Y+K9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Y+fcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_4840f243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4840f24362fab800677052f41e6075ea8378660a43621d7ab497268c36b322b4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:57:51"
  condition:
    hash.sha256(0, filesize) == "4840f24362fab800677052f41e6075ea8378660a43621d7ab497268c36b322b4"
}
```

### Sample 46: `1e0a8824261e3edb`

| Field | Value |
|---|---|
| SHA-256 | `1e0a8824261e3edb36d12fd5ce659cbb3989d4470809d2310cc56cd47da53555` |
| Family label | `unknown` |
| File name | `zxc9.exe` |
| File type | `exe` |
| First seen | `2026-08-14 20:57:48` |
| Reporter | `James_inthe_box` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1f7fc14f95158153c1fc1c5dc079af1` |
| SHA-1 | `f48325809db554e6754e26e1a3f8518a33b316ee` |
| SHA-256 | `1e0a8824261e3edb36d12fd5ce659cbb3989d4470809d2310cc56cd47da53555` |
| SHA3-384 | `cb4a36a42ea40a91416d0354bd97083ca6d568a7f2da795229b1cbe2a6d83b817a94b666b74393a4bf8468be9e10830f` |
| IMPHASH | `8e7b065c967657cca657d11206f96e23` |
| TLSH | `T1B733E90EA742A4D8C91FC1349BEA4773B6B1B81154A26B1E23E0C7211F64DEA1F3CB19` |
| SSDEEP | `384:Didi+dL5bd0tFi0huzF+2PzxM1eDdeXbGMw:eQ+p5wwcuzQ2PVMQdkKM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_1e0a8824
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e0a8824261e3edb36d12fd5ce659cbb3989d4470809d2310cc56cd47da53555"
    family = "unknown"
    file_name = "zxc9.exe"
    file_type = "exe"
    first_seen = "2026-08-14 20:57:48"
  condition:
    hash.sha256(0, filesize) == "1e0a8824261e3edb36d12fd5ce659cbb3989d4470809d2310cc56cd47da53555"
}
```

### Sample 47: `8daa6c064b47a03c`

| Field | Value |
|---|---|
| SHA-256 | `8daa6c064b47a03c85bc0eff732da07e0e8966cfc69771e3b9597cad9a155b13` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 20:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3fabcc24d9c8b12a02126d2102a48f9` |
| SHA-1 | `9d54fa92c215c6ae6eb7b238ba640c10d9ae2c2c` |
| SHA-256 | `8daa6c064b47a03c85bc0eff732da07e0e8966cfc69771e3b9597cad9a155b13` |
| SHA3-384 | `d75066d89956d7b332193fab7f0e838bf9eebf092161800a35f5188d58dc1a448d46344b3743d40db708c8fdfc1dfec7` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1CDE6334D79E166FBE9B3107CEEC21564AA76B8702735C6CB43B887606C572C0C93A723` |
| SSDEEP | `393216:shvBRRAUCOF4YauIGsvrBdBDFXMCHWUjxcuI3/PGTAI:shJHfrFxtIGsTjBDFXMb8mH/O7` |
| ICON-DHASH | `d4f8d0f0e0e971b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_8daa6c06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8daa6c064b47a03c85bc0eff732da07e0e8966cfc69771e3b9597cad9a155b13"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 20:52:32"
  condition:
    hash.sha256(0, filesize) == "8daa6c064b47a03c85bc0eff732da07e0e8966cfc69771e3b9597cad9a155b13"
}
```

### Sample 48: `769c5186f40c16fa`

| Field | Value |
|---|---|
| SHA-256 | `769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded` |
| Family label | `unknown` |
| File name | `769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded.bin` |
| File type | `exe` |
| First seen | `2026-08-14 20:51:21` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25f8beb77d6bbfd007a326d24978827e` |
| SHA-1 | `77f274a99d94bdab1709eff41f801bf893393130` |
| SHA-256 | `769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded` |
| SHA3-384 | `40ffc069124de8e7842a5dc2f20ef34b87b5ea691780db83c7f031664f2e4f647a134a78b1329422fcc4e508aaee1adc` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1DF368D0B791681A9C4DAAA35C93371A07639FC8DC73533D71EB1A6702F663D6093EB42` |
| SSDEEP | `49152:UN2/MtCsvpxxcbdHMZCKbnfmrbkdXHLbRlKLyZbAmb+/mrqlqOcP/Xk:UEqRHORSnWbkdp0KAg++rqe3Xk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_769c5186
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded"
    family = "unknown"
    file_name = "769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded.bin"
    file_type = "exe"
    first_seen = "2026-08-14 20:51:21"
  condition:
    hash.sha256(0, filesize) == "769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded"
}
```

### Sample 49: `1d118a9482bb8f30`

| Field | Value |
|---|---|
| SHA-256 | `1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e` |
| Family label | `unknown` |
| File name | `1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e.bin` |
| File type | `exe` |
| First seen | `2026-08-14 20:51:19` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9327108ce3c50647935244813d506f4d` |
| SHA-1 | `01e3a1b3b3f89bf99c183aea978f17cf890eea01` |
| SHA-256 | `1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e` |
| SHA3-384 | `90eb9899915cd35c297743cc522062b18253d35ce5a2d36e4bdb68c81076ccfabed9dc162c8a0ccb35e78c5804a8b9d7` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1C5368C0BAA51C175C48A7E34957602257B39FC4CC73533A72EB2A6703F727E64A7AB10` |
| SSDEEP | `49152:iF6fJfKDtaM7yhxdFYGOOhzX+5wyWlt1X/bFH/zJYkE4pj4XXugPaQbLbs6XNmu/:iIOTqWG3F+KfH/6knpMugikLbs006NF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_1d118a94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e"
    family = "unknown"
    file_name = "1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e.bin"
    file_type = "exe"
    first_seen = "2026-08-14 20:51:19"
  condition:
    hash.sha256(0, filesize) == "1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e"
}
```

### Sample 50: `f2b7f869036f558e`

| Field | Value |
|---|---|
| SHA-256 | `f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d` |
| Family label | `unknown` |
| File name | `f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d.bin` |
| File type | `exe` |
| First seen | `2026-08-14 20:51:17` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d4dad091692dc25b7ab60efab9fc5e3` |
| SHA-1 | `fb837122ffb8b7041986db79fdd5e908d8ec38c8` |
| SHA-256 | `f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d` |
| SHA3-384 | `9173afe8587de711d11a5ba52fe8a1e81cb3dd350e540565d6e82005c99e7f18a21081c919606eee57c937573b8afa5f` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T168066C0B6C244176DA376A3C66A61121A5E87D0CDFB4BBDB1EC17AB06FB13C04DBA315` |
| SSDEEP | `24576:vd0JxWSU2xv4RfzDMX/b/iye0tT9+dHmDXdRVaCtuwqD7Ttwlth/6SzM0+eWQktD:l0jWSU2xwVzXye0WdH6dRofz/TAt26ox` |
| ICON-DHASH | `4c126ce4d4680200` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_f2b7f869
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d"
    family = "unknown"
    file_name = "f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d.bin"
    file_type = "exe"
    first_seen = "2026-08-14 20:51:17"
  condition:
    hash.sha256(0, filesize) == "f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d"
}
```

### Sample 51: `a4b5e01c133b3da9`

| Field | Value |
|---|---|
| SHA-256 | `a4b5e01c133b3da9ae56b2d96bc003b0fb8431c2f454f25984428d3c7212c6cc` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-08-14 20:50:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3ce8dad8acac295fb0914488e1b6f09` |
| SHA-1 | `9dd17fb275325a62596f7a987ae89392b2194a1e` |
| SHA-256 | `a4b5e01c133b3da9ae56b2d96bc003b0fb8431c2f454f25984428d3c7212c6cc` |
| SHA3-384 | `8023f327017cae6b9b1334799ae0ba1c190f1ba1b07eb8c3887188bfea5c3630089eae82b06061ee37f4eff433d66db1` |
| TLSH | `T177144C469A418B13C4C62B7AFADF41453323A764D3EB730689287FB43F86B9E0E67505` |
| TELFHASH | `t1b14123325b3695261eb1cd14e8ed27f1190f46275644aa32ef6688cc600908ee62bd4f` |
| SSDEEP | `6144:+j1o77VSsxzqa6IjHa5A6fWRfz+bUBZD++mXcJM/9wUcEQt:ao77VSs0IjHa5A6fWRfz+IB933e/fA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_a4b5e01c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4b5e01c133b3da9ae56b2d96bc003b0fb8431c2f454f25984428d3c7212c6cc"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-14 20:50:43"
  condition:
    hash.sha256(0, filesize) == "a4b5e01c133b3da9ae56b2d96bc003b0fb8431c2f454f25984428d3c7212c6cc"
}
```

### Sample 52: `b8c1f1f1cf3815c6`

| Field | Value |
|---|---|
| SHA-256 | `b8c1f1f1cf3815c67b4a840c1fc16e05f190717a3cc5288f5307b3af06578da7` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-08-14 20:49:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfd55df0a03b07539ed8260515071cb3` |
| SHA-1 | `7b9891593f1a1c478f3ae60daf705942b6963ba3` |
| SHA-256 | `b8c1f1f1cf3815c67b4a840c1fc16e05f190717a3cc5288f5307b3af06578da7` |
| SHA3-384 | `1b219b63d7ef8705d569ac9a93491b0138ed00a01db91535915e2a404d25b594678be49ab5775a5ea9ff03a4e4f3e455` |
| TLSH | `T16F730231B04AECBDDDF05769A294DC0C1B283ABCD990F16BBB16EA44255290209E57EF` |
| SSDEEP | `1536:FTaMZ5jrLKb9PCjoG/VZ70I+JPjRBGbC8ELPLOVCooSC8hFUoN4uh0:pKRP8dZ70Z76ePLYCoZCmSYh0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_b8c1f1f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8c1f1f1cf3815c67b4a840c1fc16e05f190717a3cc5288f5307b3af06578da7"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-14 20:49:55"
  condition:
    hash.sha256(0, filesize) == "b8c1f1f1cf3815c67b4a840c1fc16e05f190717a3cc5288f5307b3af06578da7"
}
```

### Sample 53: `08f41cf391af5b60`

| Field | Value |
|---|---|
| SHA-256 | `08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172` |
| Family label | `unknown` |
| File name | `08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172.bin` |
| File type | `zip` |
| First seen | `2026-08-14 20:39:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ec599b09e83559bae45eb45d2aec618` |
| SHA-1 | `cc87042bba9a70ac18de18712c8ea0acd86238d6` |
| SHA-256 | `08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172` |
| SHA3-384 | `c04b1ac4a9d81e22f1ebbee531b6f5a4b92d65706d4df08b3c8c235a23888038448f79eedb09f07e8a967ec89eb75794` |
| TLSH | `T141C42367226F72500DFE92ED4E4156186D3D8E322A00A6FE55D8C9CE8719F0ECE35E8D` |
| SSDEEP | `12288:weCEhts9qO3g/ALyYG0ZaDajTCXMO8xzDOeQakI:Xt2A/f0Za6TCXKBxlb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_08f41cf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172"
    family = "unknown"
    file_name = "08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172.bin"
    file_type = "zip"
    first_seen = "2026-08-14 20:39:43"
  condition:
    hash.sha256(0, filesize) == "08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172"
}
```

### Sample 54: `41b84dfc97d534cb`

| Field | Value |
|---|---|
| SHA-256 | `41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92` |
| Family label | `unknown` |
| File name | `41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92.bin` |
| File type | `zip` |
| First seen | `2026-08-14 20:39:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3f9552c0952d55082629ddf62b2375e` |
| SHA-1 | `ea3e5333d63d3e69adeb27d37d0ebe0b5937db0e` |
| SHA-256 | `41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92` |
| SHA3-384 | `cb4f75c35f35a6a705d2eeabbc08892a356f3375533f79e9c550ff8c6d31ecb1ef67c6ba8d3fcbd4554869073695993d` |
| TLSH | `T193B423F5A7606BCC9D20522E2F4A27CE19274B41B403C54A1ED2875A421F6FF4E7AD9C` |
| SSDEEP | `12288:EBRdpQ73iBVYWNCwvEXgbvM0a4OTHiQIIFzuK9Gd9IUS:EHUw2Wo9XgbM0azTHiQIouDO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_41b84dfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92"
    family = "unknown"
    file_name = "41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92.bin"
    file_type = "zip"
    first_seen = "2026-08-14 20:39:39"
  condition:
    hash.sha256(0, filesize) == "41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92"
}
```

### Sample 55: `9f9bf79cde61182c`

| Field | Value |
|---|---|
| SHA-256 | `9f9bf79cde61182ca08d425604c51b9d0913b072f8bfc325693677abbc359260` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-14 20:36:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61f02412c6d3f4219486f8b26a5b9776` |
| SHA-1 | `fa9d5d8d26c496d7d7ba65148abd09798122cc50` |
| SHA-256 | `9f9bf79cde61182ca08d425604c51b9d0913b072f8bfc325693677abbc359260` |
| SHA3-384 | `10a5ae90dadcd525ad052621426fe91c7877d6620b97eaba0f51fd1dbe63d3180c7f8294fbb750d9cf13f08a36bde907` |
| TLSH | `T14BE4C80B6E228F7DF674873147F70A24ABAD33D617E1D581D2ADC1142F2128E591FBA8` |
| TELFHASH | `t12cb13899293913a4a7545d8d46dcff328d6328ef2a561c33de50e89ea71ba835e10c1c` |
| SSDEEP | `6144:VhgrS63eTy1MnKqo2NLA1V894V8VLydLbxv8/Wakm8CRB4Pzihg3n3BgpJcISJfA:zgIWwBo2iV10ocsndSNphqnzb2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_9f9bf79c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f9bf79cde61182ca08d425604c51b9d0913b072f8bfc325693677abbc359260"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-14 20:36:16"
  condition:
    hash.sha256(0, filesize) == "9f9bf79cde61182ca08d425604c51b9d0913b072f8bfc325693677abbc359260"
}
```

### Sample 56: `9068808aff079079`

| Field | Value |
|---|---|
| SHA-256 | `9068808aff079079e74325af79f7166dc6da8ff2c008dca4823411e992052288` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-08-14 20:32:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4c8a4f4de0fa36a550cb05bff3c94bd` |
| SHA-1 | `6c18bd5b9124f6c0b94eb18df26a53c96771937b` |
| SHA-256 | `9068808aff079079e74325af79f7166dc6da8ff2c008dca4823411e992052288` |
| SHA3-384 | `59fd83c8584d4d47a82a9be1d005f0cb715c12029f5799734cccf5ad09a65f43e18ac9e4859f4ba5a80d2d0bf687363b` |
| TLSH | `T1B5E3B61E6E319F7DF7A8C33447B78B20A25973D622E0D645E2ACD6051E6034E641FFA8` |
| TELFHASH | `t15631c9584a7413e067315c8d5aadff7bd2b030df6b126d378d11a86ab76d8825e20c0c` |
| SSDEEP | `3072:y658DhHfjsOHRWbi064Dik7zWy965Jnfn:y65shHIOHR1064DiSfQnfn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_9068808a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9068808aff079079e74325af79f7166dc6da8ff2c008dca4823411e992052288"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-14 20:32:39"
  condition:
    hash.sha256(0, filesize) == "9068808aff079079e74325af79f7166dc6da8ff2c008dca4823411e992052288"
}
```

### Sample 57: `896f63d1435cd220`

| Field | Value |
|---|---|
| SHA-256 | `896f63d1435cd22055e0e9c1d240fb51291d8e870ce4e1df89c2922ffdd713ff` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-08-14 20:32:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2ff1a31fae2e5c6121706b5fe448abe` |
| SHA-1 | `cef2a70afcf5d074de08414de40e31fea15819dc` |
| SHA-256 | `896f63d1435cd22055e0e9c1d240fb51291d8e870ce4e1df89c2922ffdd713ff` |
| SHA3-384 | `22cbe57249b3692a80c2bbb62c3f87156f20c48b3b51156dce46774d7dfda577a658e75f757d882a3db071917c1b711e` |
| TLSH | `T1A833F1F426E1126BD62C267C29FADB145E414ED09A178C62F7A8E1C7CF991903D83BE1` |
| SSDEEP | `1536:IcZ8/5tZ0/7qz3L7JgR/2lPSjmlSmVJu8:IR/r1vJ3jlSmVQ8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_896f63d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896f63d1435cd22055e0e9c1d240fb51291d8e870ce4e1df89c2922ffdd713ff"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-14 20:32:22"
  condition:
    hash.sha256(0, filesize) == "896f63d1435cd22055e0e9c1d240fb51291d8e870ce4e1df89c2922ffdd713ff"
}
```

### Sample 58: `9077718299112945`

| Field | Value |
|---|---|
| SHA-256 | `9077718299112945704be6a44d2f7e927a18e449c33e77dc523673cafbfedd35` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-14 20:32:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58ec74d3a458a177e8e7da867e3c1830` |
| SHA-1 | `f7323c6188a0f0e8b4dd49cac0795d8889b2b4d6` |
| SHA-256 | `9077718299112945704be6a44d2f7e927a18e449c33e77dc523673cafbfedd35` |
| SHA3-384 | `c054c6b15f4d87ecd4bb26cc3f5ecb4d7997ce2fc9a09a9da1738c43223ea97fc1bc03183b9fc41c8b1094ca897fef7d` |
| TLSH | `T197236D661A857C14AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10971D` |
| SSDEEP | `768:IXRWNGxVr9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:clxecr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_90777182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9077718299112945704be6a44d2f7e927a18e449c33e77dc523673cafbfedd35"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:32:21"
  condition:
    hash.sha256(0, filesize) == "9077718299112945704be6a44d2f7e927a18e449c33e77dc523673cafbfedd35"
}
```

### Sample 59: `313dbce684c3b044`

| Field | Value |
|---|---|
| SHA-256 | `313dbce684c3b044d5d5fd996d21b9af717241b4c413db5e401417147fbd408b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-14 20:26:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89dc363634e3ec2ea8c18c22ebcc4abd` |
| SHA-1 | `6ab914cb19c2e348934754b5e43fef2ea09b6668` |
| SHA-256 | `313dbce684c3b044d5d5fd996d21b9af717241b4c413db5e401417147fbd408b` |
| SHA3-384 | `560d8a8bf9fe55279aa5648c0357cbbe1ddf7b356fc589f56d48122363262596ab967290cd4efc0d9901f86f2a4e4423` |
| TLSH | `T13BC28D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:X8vCB+25j6es8RC9FYpMSUpi+20qUpi+20YQX:X8l25Jkd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_313dbce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "313dbce684c3b044d5d5fd996d21b9af717241b4c413db5e401417147fbd408b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:26:17"
  condition:
    hash.sha256(0, filesize) == "313dbce684c3b044d5d5fd996d21b9af717241b4c413db5e401417147fbd408b"
}
```

### Sample 60: `548bb9f32f100985`

| Field | Value |
|---|---|
| SHA-256 | `548bb9f32f10098578ac482ed67f827aeae36bfb32845dd16556d532ea19fa05` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-14 20:23:27` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a50be892a4abea255cc2b0407e627589` |
| SHA-1 | `16ffb5f58d32ddd1575a655aeb6728075a8257f4` |
| SHA-256 | `548bb9f32f10098578ac482ed67f827aeae36bfb32845dd16556d532ea19fa05` |
| SHA3-384 | `c97932db2f49bd31352ef7d4cfb38f875e23754174185065c0455855b238ec4e126545563ec2e146d94e986f2a663258` |
| IMPHASH | `020b3a2ad3ae3205473f7ecc7bcb6961` |
| TLSH | `T10C145B07E6828CEDE9BAC5708E97D237E670B8444574EB2B2F208F356D61F50793DA48` |
| SSDEEP | `3072:Q6Mc6u1zSYDc8pfxhMakzHJTsikp1Ucmtbvu3qLR9:0Z4S3EhMawpTsT1UcmtbWAR9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_548bb9f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548bb9f32f10098578ac482ed67f827aeae36bfb32845dd16556d532ea19fa05"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 20:23:27"
  condition:
    hash.sha256(0, filesize) == "548bb9f32f10098578ac482ed67f827aeae36bfb32845dd16556d532ea19fa05"
}
```

### Sample 61: `5c9994823d70eeaa`

| Field | Value |
|---|---|
| SHA-256 | `5c9994823d70eeaa4c95fa42af69ee5e777510e7cfbdd407ec21205b44979c1b` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-14 20:18:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `495c87bd94a85c621baa527bbc8bf0e3` |
| SHA-1 | `196aecb20341149346c275145cbd85ff14b2aec3` |
| SHA-256 | `5c9994823d70eeaa4c95fa42af69ee5e777510e7cfbdd407ec21205b44979c1b` |
| SHA3-384 | `22d80bbea484f1d946c7a80defee1c5c8c377d36ff1f2f990ea9d76dd5028920f036736a5fa7c2cb5f5b51ca5685ebf6` |
| TLSH | `T1E9B32A56B8828B21D6C616BBFE1E018D3313177CE3EE73128D146F24678B96B0E77516` |
| TELFHASH | `t11641ddf7a7609edd37f6444c830a71490afa3d2b1b2a3487990d674fe253ad1b02dc22` |
| SSDEEP | `3072:JwM9otCt65gKAzAhaIi7aI3GstCNfrwd54UG37:JwM9oUt65gMUIYauGstCN44UG7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_5c999482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c9994823d70eeaa4c95fa42af69ee5e777510e7cfbdd407ec21205b44979c1b"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-14 20:18:42"
  condition:
    hash.sha256(0, filesize) == "5c9994823d70eeaa4c95fa42af69ee5e777510e7cfbdd407ec21205b44979c1b"
}
```

### Sample 62: `2d0c8c72f8d09535`

| Field | Value |
|---|---|
| SHA-256 | `2d0c8c72f8d095358ba3237d833ceb20971a6255cab8d76eb3631a016bbcd91c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-14 20:18:12` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72027218f14c4ec8375aa7e980373358` |
| SHA-1 | `70965ee8eff5a8597bf910d3ce0642d12981df20` |
| SHA-256 | `2d0c8c72f8d095358ba3237d833ceb20971a6255cab8d76eb3631a016bbcd91c` |
| SHA3-384 | `b55b17f40bc6df1a6bac0d2dd5fa8177f1be757a2b8b98b80f9100ace6947bfeea4f69f88fca5a37396b918548c9ade2` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1D4764A07ED6514E9C0BED131897696627F617C480B3123D32B90F6287FB6BD0AEBA354` |
| SSDEEP | `49152:yy9ac91p6jYazbi+xbkEsLiYpTkmOcPlfF4QS5UoNrRaQmoZWRdmvzSMj9ICPAcP:yyssXYAoL91ZW4zRCOp9QE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_2d0c8c72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d0c8c72f8d095358ba3237d833ceb20971a6255cab8d76eb3631a016bbcd91c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 20:18:12"
  condition:
    hash.sha256(0, filesize) == "2d0c8c72f8d095358ba3237d833ceb20971a6255cab8d76eb3631a016bbcd91c"
}
```

### Sample 63: `b20f7d9fe9143a2c`

| Field | Value |
|---|---|
| SHA-256 | `b20f7d9fe9143a2cb2650f33f2d63f93f0d03a171da810e42d4a256de4d81bd5` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-14 20:18:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f7eeba796b9e88d872aa9056d8a4aa9` |
| SHA-1 | `22c38bbd11a510a087e3cb228e44a06f1a6a6c25` |
| SHA-256 | `b20f7d9fe9143a2cb2650f33f2d63f93f0d03a171da810e42d4a256de4d81bd5` |
| SHA3-384 | `9f41a44a61f19784862fbe4450fab8172325416aa8b0aa38fba1c674605b85a6bf26a70726ebe9793460f6a0afbf2be6` |
| TLSH | `T1A933F181A42AFAD5E335A132FA5C45CB324D96F60594B41B172A85A8D8D70DBD3B23C3` |
| SSDEEP | `1536:1k5pYMjge4PmvZabW6f2TPorkBmG7EOXL4:arjqM8C6uTPorEEOXL4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_b20f7d9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20f7d9fe9143a2cb2650f33f2d63f93f0d03a171da810e42d4a256de4d81bd5"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-14 20:18:01"
  condition:
    hash.sha256(0, filesize) == "b20f7d9fe9143a2cb2650f33f2d63f93f0d03a171da810e42d4a256de4d81bd5"
}
```

### Sample 64: `ce264702b5d9fa27`

| Field | Value |
|---|---|
| SHA-256 | `ce264702b5d9fa27e53da389d15be01cd0efb83713da99824a714a61f71df43a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-14 20:15:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31d5963cbb53faf3bf65cb1294808bdb` |
| SHA-1 | `7138b0d0f3eede7e500b5ebf242412560f43c8e7` |
| SHA-256 | `ce264702b5d9fa27e53da389d15be01cd0efb83713da99824a714a61f71df43a` |
| SHA3-384 | `d830bf32a703467c78c0e04d5f11122a5167579932e2af2cb8875bb2a2bcd5276776882540c2c912cb855c5097466939` |
| TLSH | `T1E7C27D956A867C44BEC98A3E4CBE2B0D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:i8vCB+25j6es8R79FYpMSUpi+20qUpi+20YQX:i8l25JNd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_ce264702
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce264702b5d9fa27e53da389d15be01cd0efb83713da99824a714a61f71df43a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:15:34"
  condition:
    hash.sha256(0, filesize) == "ce264702b5d9fa27e53da389d15be01cd0efb83713da99824a714a61f71df43a"
}
```

### Sample 65: `5320d565de984280`

| Field | Value |
|---|---|
| SHA-256 | `5320d565de984280aed253f7ba82c3a5f9d6a7be23300e746e10c63f2b583cbd` |
| Family label | `unknown` |
| File name | `ue` |
| File type | `exe` |
| First seen | `2026-08-14 20:12:14` |
| Reporter | `monitorsg` |
| Tags | `exe, KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `488e038d75bd71a749dcb98ca5f0006d` |
| SHA-1 | `0e555954137d88bde2aac58051f507c1c886e2e6` |
| SHA-256 | `5320d565de984280aed253f7ba82c3a5f9d6a7be23300e746e10c63f2b583cbd` |
| SHA3-384 | `b517988d3f2e3f5860feb8a57d769e8ca119dfbaba3de0f2832eba35b435ca1ce10a97cbbba67ab5b35271e8f740e3c2` |
| TLSH | `T133F64A77E4B7635DCF6893AB146C6E2353E23E08A1E7780C35803BB626545CE0FA15E6` |
| SSDEEP | `98304:iP2Io9gIgVYl6KY5LHbWFwgfbEO+F8Yjs5JUsiWGJV7NLLSijeUxfb1sDhrgH7Z/:KzzT1H59+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_5320d565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5320d565de984280aed253f7ba82c3a5f9d6a7be23300e746e10c63f2b583cbd"
    family = "unknown"
    file_name = "ue"
    file_type = "exe"
    first_seen = "2026-08-14 20:12:14"
  condition:
    hash.sha256(0, filesize) == "5320d565de984280aed253f7ba82c3a5f9d6a7be23300e746e10c63f2b583cbd"
}
```

### Sample 66: `3ce639bc2635ef7a`

| Field | Value |
|---|---|
| SHA-256 | `3ce639bc2635ef7a4eb81dbe22a6d3a87c34d65477ac83a420b3480baeffc145` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-08-14 20:11:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `890b30534963c6b309afb674b5e9bfc5` |
| SHA-1 | `a929d8ced6ebe9a6c12146adcdf82d26d7d1c8d1` |
| SHA-256 | `3ce639bc2635ef7a4eb81dbe22a6d3a87c34d65477ac83a420b3480baeffc145` |
| SHA3-384 | `82fc639e3cde5ade784ddfecf3386db496233aeec4e2ac9b9ce94b763229f12d4a287801069752e80f567157a25d1ec1` |
| TLSH | `T138B34AD7F400DE7DF80AD73B40574A16B231B7514A830F362257B967AEB61E86827F82` |
| SSDEEP | `3072:nWeVxQG8NOfIjGclGwJ0tGuQ5QnXM9Ae+:tKG8NOfIDStGF5QCAe+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_3ce639bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ce639bc2635ef7a4eb81dbe22a6d3a87c34d65477ac83a420b3480baeffc145"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-08-14 20:11:21"
  condition:
    hash.sha256(0, filesize) == "3ce639bc2635ef7a4eb81dbe22a6d3a87c34d65477ac83a420b3480baeffc145"
}
```

### Sample 67: `6098837b41d4a66b`

| Field | Value |
|---|---|
| SHA-256 | `6098837b41d4a66b3d5a0137823a9331695775b4e38f86c4ab91b73a9c3eec8c` |
| Family label | `unknown` |
| File name | `main.archs38` |
| File type | `elf` |
| First seen | `2026-08-14 20:09:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52d0ae389b03b3451d060d770d45cd86` |
| SHA-1 | `4b0b15244c87f6664ea5e403624e5c805f110b24` |
| SHA-256 | `6098837b41d4a66b3d5a0137823a9331695775b4e38f86c4ab91b73a9c3eec8c` |
| SHA3-384 | `c019c2e2ac0c815cd262a28e6b2d69beaaf82f75cf5bff5aeaa46b6ac106cc3fe60b3fddd74a0e1d862375e948b9ca5d` |
| TLSH | `T192A36C47770B2880F82102F1A3DDA3E03F1561DBAF321EB7586A62F76F635991D06B52` |
| SSDEEP | `1536:Hg5g1vOwpJ1sdUDnL3f5Cxd9lEZ2KUa34jgLKCUn5p5M/LW:Ag9hsdUDnLSlHPgzhq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_6098837b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6098837b41d4a66b3d5a0137823a9331695775b4e38f86c4ab91b73a9c3eec8c"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-14 20:09:14"
  condition:
    hash.sha256(0, filesize) == "6098837b41d4a66b3d5a0137823a9331695775b4e38f86c4ab91b73a9c3eec8c"
}
```

### Sample 68: `529dc632c717f078`

| Field | Value |
|---|---|
| SHA-256 | `529dc632c717f0785a23c47db89ce152fdf1e42c7f55def460cc62df64a7778f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-14 20:09:12` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ced2a9ad52e09878027a14aa9290dc16` |
| SHA-256 | `529dc632c717f0785a23c47db89ce152fdf1e42c7f55def460cc62df64a7778f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_529dc632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "529dc632c717f0785a23c47db89ce152fdf1e42c7f55def460cc62df64a7778f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 20:09:12"
  condition:
    hash.sha256(0, filesize) == "529dc632c717f0785a23c47db89ce152fdf1e42c7f55def460cc62df64a7778f"
}
```

### Sample 69: `effad2cfdbb44e80`

| Field | Value |
|---|---|
| SHA-256 | `effad2cfdbb44e803001b7108acfad70cb0b42dc324055f275f3d73cf4d148cf` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-14 20:09:03` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18963050dfe45dab78f94ff01569937f` |
| SHA-256 | `effad2cfdbb44e803001b7108acfad70cb0b42dc324055f275f3d73cf4d148cf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_effad2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "effad2cfdbb44e803001b7108acfad70cb0b42dc324055f275f3d73cf4d148cf"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 20:09:03"
  condition:
    hash.sha256(0, filesize) == "effad2cfdbb44e803001b7108acfad70cb0b42dc324055f275f3d73cf4d148cf"
}
```

### Sample 70: `a9ba51f0fde56b9f`

| Field | Value |
|---|---|
| SHA-256 | `a9ba51f0fde56b9fe59dbaee6a3812631471a8d45b9f90b6aee06db927b86fb7` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-08-14 20:04:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae2ae58a1c350e1144c7e9a331a5e647` |
| SHA-1 | `af3c7d157cb452f9075147867d361778d058b92e` |
| SHA-256 | `a9ba51f0fde56b9fe59dbaee6a3812631471a8d45b9f90b6aee06db927b86fb7` |
| SHA3-384 | `045a129c0b4ae1a654f9de17798d3651bf353a909e0d5512a9cd3646876575d737023f2a35f587825602f99893241c97` |
| TLSH | `T174A39E72C4252D54D0945AB4B8B98A3C1F23A44082C71FFB9ADAC67B8087EECF1197F5` |
| SSDEEP | `3072:FQZYlBDWEdc62sMHrvmjGAqo+aCL/zDj:FcehO1Fb3Lfj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_a9ba51f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9ba51f0fde56b9fe59dbaee6a3812631471a8d45b9f90b6aee06db927b86fb7"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-08-14 20:04:39"
  condition:
    hash.sha256(0, filesize) == "a9ba51f0fde56b9fe59dbaee6a3812631471a8d45b9f90b6aee06db927b86fb7"
}
```

### Sample 71: `036000bac9d3ec06`

| Field | Value |
|---|---|
| SHA-256 | `036000bac9d3ec067332774b1b8a9b057554d255ff845f801f5d882a5ed9aba5` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-14 20:00:02` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e2b346a5ee1dec32c0b064f314c9299` |
| SHA-1 | `f019aa6580f9d7a6b749bb55bfcc798d8f4c5d2c` |
| SHA-256 | `036000bac9d3ec067332774b1b8a9b057554d255ff845f801f5d882a5ed9aba5` |
| SHA3-384 | `6294df99eae819f259b2dc1cdaa792ba5cf32ebb620a81824fb0f9c2c4668e7d67e6ae5e845ed86463f55244e7587688` |
| TLSH | `T12631239B40201A311102DE4E7762354D729EA5FB2C9FDBD4DC5C4EA992893CCF361F99` |
| SSDEEP | `24:Lanvi1SDHIaFlbXNYLjuDQ+5aMEFlRqvs2gQzN:2nviEDHIaF9FDQ+5a5Nqvs4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_036000ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "036000bac9d3ec067332774b1b8a9b057554d255ff845f801f5d882a5ed9aba5"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-14 20:00:02"
  condition:
    hash.sha256(0, filesize) == "036000bac9d3ec067332774b1b8a9b057554d255ff845f801f5d882a5ed9aba5"
}
```

### Sample 72: `24e9f68600627882`

| Field | Value |
|---|---|
| SHA-256 | `24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8` |
| Family label | `unknown` |
| File name | `24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8.exe` |
| File type | `exe` |
| First seen | `2026-08-14 19:59:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97afc6703e0f1ee55628f9ca274cfd82` |
| SHA-1 | `83d9da7c48e653ce205e06bc76434c316109ca4a` |
| SHA-256 | `24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8` |
| SHA3-384 | `6a8861e136e2033a146d6da7138d93f5b7abe289485a4de3e532667d7c4fabd866cdec32c7eb42a476cd88fab00d3838` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1D6D52356B5B11D7AC877C7B2CF83F16DB06A77C44A204E0BB5DC2A009E52A684E3B371` |
| SSDEEP | `49152:TMCNYPmEmqs+cMBdVEMrrZhzXw1EVJ8Qfz0XEJVRLNYPevZu:T54m1qHcMBdZBhBV2c0UJXO2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_24e9f686
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8"
    family = "unknown"
    file_name = "24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8.exe"
    file_type = "exe"
    first_seen = "2026-08-14 19:59:41"
  condition:
    hash.sha256(0, filesize) == "24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8"
}
```

### Sample 73: `981525a1d8040382`

| Field | Value |
|---|---|
| SHA-256 | `981525a1d804038294a0cf24fe434f4f44e82cb93c2e324c398829f0f4e1907c` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-08-14 19:55:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb761c5db45d6d9455da6110f53140fd` |
| SHA-1 | `b1eb4ffa3210ce74f151ce4c08e5fc1530c27fce` |
| SHA-256 | `981525a1d804038294a0cf24fe434f4f44e82cb93c2e324c398829f0f4e1907c` |
| SHA3-384 | `5f503449702dd808ca02a43ac12124dfe4295159f4632a737c195bcaddb7151592f3083201207828cc698a619903c97e` |
| TLSH | `T175936CC5B743E4F5F8650539213BA7728633F4351029DA8ADBA8E932F8A1641EB1735C` |
| TELFHASH | `t1d841e7fa2d7e0ce8b7c45805a21d5f616e5c973b287036b315f2583436ab94192bbc3d` |
| SSDEEP | `1536:tdg4As8GCBk/bu6Y91jK9e5tczLmasb8KwwUNPlFvXLsW9atq8eYWQmNhe:fg4AlJBk/bCjK9UtJl8Kww8PlBbsLtrd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_981525a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981525a1d804038294a0cf24fe434f4f44e82cb93c2e324c398829f0f4e1907c"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-14 19:55:52"
  condition:
    hash.sha256(0, filesize) == "981525a1d804038294a0cf24fe434f4f44e82cb93c2e324c398829f0f4e1907c"
}
```

### Sample 74: `7780fb81a5342b74`

| Field | Value |
|---|---|
| SHA-256 | `7780fb81a5342b747a9796b6ba6a401c0259faad077cf9ca739ef70e14e75c7c` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-08-14 19:55:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59e6dd5975c7d59bdad6a7727b43497d` |
| SHA-1 | `af995e59c8814dee2eb5482b2ce2142893a2b2fc` |
| SHA-256 | `7780fb81a5342b747a9796b6ba6a401c0259faad077cf9ca739ef70e14e75c7c` |
| SHA3-384 | `8698f8e6d2e545304d9577fba310fad67da4d199d10fd1542c10646ea4e737308320ac6710a6b79e5ea18449f2109a61` |
| TLSH | `T1EE23F10202E04FC5E1A951B8E1DF7E4F6450B0581D34E8F6EF1E642D8CE3725A96ABE7` |
| SSDEEP | `768:tpFdfC+9Ox+6lYUg01B1AY4UoLJKJIvEIs/RI3TaYtkjWRZKJdjnbcuyD7UGQRjW:BdK+9U+QXg01N4U+4iEIFTBsWRZiZno5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_7780fb81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7780fb81a5342b747a9796b6ba6a401c0259faad077cf9ca739ef70e14e75c7c"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-14 19:55:17"
  condition:
    hash.sha256(0, filesize) == "7780fb81a5342b747a9796b6ba6a401c0259faad077cf9ca739ef70e14e75c7c"
}
```

### Sample 75: `26e37807d3f5562c`

| Field | Value |
|---|---|
| SHA-256 | `26e37807d3f5562c48d14452f81b586fd963831f3d185d2e150e0080f9013ec5` |
| Family label | `unknown` |
| File name | `NotaFiscal_1546_AshPin_8755.zip` |
| File type | `zip` |
| First seen | `2026-08-14 19:54:47` |
| Reporter | `johnk3r` |
| Tags | `acess-gerenciadorarcosxz-com, banker, downloader, eletronica-emitida-comunicadodocfiscal-com, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00d8c525557e01b5db2b484a6e713632` |
| SHA-1 | `72c72917b7b16cd596e03ee70b60c3d757ff4279` |
| SHA-256 | `26e37807d3f5562c48d14452f81b586fd963831f3d185d2e150e0080f9013ec5` |
| SHA3-384 | `2bb7f8a7806915d464e4a08b5c65867e3d167ac0b8405093e57b0c4262093152697fd15a76d2b6f8ec3c5669d733f111` |
| TLSH | `T1488372E4D80439AB0687951274E52D2C3EE5133D9DAF50CA4978FFB60166B26EF9FC80` |
| SSDEEP | `768:NqF7nqt29OKyYOfhp8DC97tcBlR+D/rxCHTReSpXEKf8bGFch7r+O2sr9dmGYL6q:UFeG+6CzUodqLhWo0laIdNi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_26e37807
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e37807d3f5562c48d14452f81b586fd963831f3d185d2e150e0080f9013ec5"
    family = "unknown"
    file_name = "NotaFiscal_1546_AshPin_8755.zip"
    file_type = "zip"
    first_seen = "2026-08-14 19:54:47"
  condition:
    hash.sha256(0, filesize) == "26e37807d3f5562c48d14452f81b586fd963831f3d185d2e150e0080f9013ec5"
}
```

### Sample 76: `958f41d1487994ca`

| Field | Value |
|---|---|
| SHA-256 | `958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3` |
| Family label | `CoinMiner` |
| File name | `958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3.exe` |
| File type | `exe` |
| First seen | `2026-08-14 19:54:36` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57dacba3658cf6df28ae9d54c10c98c9` |
| SHA-1 | `f3d99d574240983bcf016ef1c477d2d3c764966a` |
| SHA-256 | `958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3` |
| SHA3-384 | `c87afc1d7678974f17096dcfa4adbdbbbf256d1303701689ab7997656e8e716156b3d2685b3f8c3d7e3da7fb34a9b744` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1923633DB7CC311B2D455CBB4A65770AE343A3F61CE61BC0B7A8DA90E8D66E0561383C6` |
| SSDEEP | `98304:9Q3RDgFUk/LBv8B8BG9nbnlzN9DwTctrocyAQMdyM+h2Uu0ppJ:9ftp8B8BG9jlR9q2rocAgyM+hO0B` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_076_958f41d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3"
    family = "CoinMiner"
    file_name = "958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3.exe"
    file_type = "exe"
    first_seen = "2026-08-14 19:54:36"
  condition:
    hash.sha256(0, filesize) == "958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3"
}
```

### Sample 77: `dc33f06c86f021af`

| Field | Value |
|---|---|
| SHA-256 | `dc33f06c86f021af72cc89e1feafa16dad624d43a79242ab738518480a0aef88` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 19:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56160fa06b16e3822879e77aa47f0764` |
| SHA-1 | `6e6db8bfff48fb23ca12b33a4c0272d787633e06` |
| SHA-256 | `dc33f06c86f021af72cc89e1feafa16dad624d43a79242ab738518480a0aef88` |
| SHA3-384 | `418d277e5ffe9d60ef00a55b18f3cb6c2e81a83ee62a05f1b22742b5111adcfc9a10169f4f45d379a6833218ea21a436` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T127E63308EAE050FDD9F3153CDAE35036EA79387A0B7686DB87A893E42E131D04D36653` |
| SSDEEP | `393216:4n6/UNDJdBcUwZt1CVqaln7FXMCHWUjqycuI3/PGTAI:46/+DJd+I5dFXMb8qPH/O7` |
| ICON-DHASH | `7071e4d6e6e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_dc33f06c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc33f06c86f021af72cc89e1feafa16dad624d43a79242ab738518480a0aef88"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 19:52:30"
  condition:
    hash.sha256(0, filesize) == "dc33f06c86f021af72cc89e1feafa16dad624d43a79242ab738518480a0aef88"
}
```

### Sample 78: `f06db00d66ee3be3`

| Field | Value |
|---|---|
| SHA-256 | `f06db00d66ee3be3c536bd1cde95514c852ca08261af889acef4e087005c6a6e` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-08-14 19:51:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1593a1ac3d948a483bdfd20424c6d395` |
| SHA-1 | `a9e14d8e4c1d585622a08e17982f12bbdb60e42f` |
| SHA-256 | `f06db00d66ee3be3c536bd1cde95514c852ca08261af889acef4e087005c6a6e` |
| SHA3-384 | `f94aad61fb633aee4a7316c312b110cc0d5dcceabd83f7aa4d96cd896c6d2188b43da67b4b827f398ff864ebf9c637fd` |
| TLSH | `T14FB34C32B979092BC4D0B87B61F74765F2F2474A21A8CA1E7D710ECDAF6464032177BA` |
| SSDEEP | `1536:f7fDSPxPgpKDMM8OPKtduja6cPm52lb/x/7VtfifN95fNCXQTfDtMmC:Df26YMOPKtohJ5OxZNifNPVU/mC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_f06db00d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f06db00d66ee3be3c536bd1cde95514c852ca08261af889acef4e087005c6a6e"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-08-14 19:51:13"
  condition:
    hash.sha256(0, filesize) == "f06db00d66ee3be3c536bd1cde95514c852ca08261af889acef4e087005c6a6e"
}
```

### Sample 79: `63eedb85b370d3d5`

| Field | Value |
|---|---|
| SHA-256 | `63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33` |
| Family label | `Vidar` |
| File name | `63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33.exe` |
| File type | `exe` |
| First seen | `2026-08-14 19:49:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, Vidar, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9c60eb51354ab07885428d7b868ade6` |
| SHA-1 | `89dba32d78049d5650f10eb53173461a4969b673` |
| SHA-256 | `63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33` |
| SHA3-384 | `323790af57401f0615cc80069e1ecfce77622d87ffe39637ab7571a3f5afde7a825693ad92f2e11f71317a50cd765ddf` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T166D40109B7D650ECE16B8578C8514672FB7B3D124380AB7F0350CB76AF239A1BD29B61` |
| SSDEEP | `12288:6VrlcFe90d1Z9WMS+REyrCtB1e6iCChlsjuC3BGVGPJgKeM27FdX8jF:lFeud1SGEoCtbeP32juC3BZSKx+tEF` |
| ICON-DHASH | `696a6ee2b2b2c2cc` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_079_63eedb85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33"
    family = "Vidar"
    file_name = "63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33.exe"
    file_type = "exe"
    first_seen = "2026-08-14 19:49:39"
  condition:
    hash.sha256(0, filesize) == "63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33"
}
```

### Sample 80: `5ee2f468fac76514`

| Field | Value |
|---|---|
| SHA-256 | `5ee2f468fac76514a39aac80f78a48a36a3a6585460017bfccca54e4afeb13c2` |
| Family label | `unknown` |
| File name | `ue` |
| File type | `exe` |
| First seen | `2026-08-14 19:28:40` |
| Reporter | `monitorsg` |
| Tags | `exe, KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `082587256ff1ecbed29ca78dbfee706d` |
| SHA-1 | `4f70d46d66a362d4c0ddc1242443223f20b9ca9c` |
| SHA-256 | `5ee2f468fac76514a39aac80f78a48a36a3a6585460017bfccca54e4afeb13c2` |
| SHA3-384 | `33ae30659f4ab67e08c23ee0c099f8ea40919d1608e4ba42b58374f5e2f7c9bacaec0c705ee9738b8a8dbd2747d5f6fd` |
| TLSH | `T18EF65B77E8B7231DDE6493AB145C6E2352E23E0CA2E7B80C35843BB536545CE0FA15E6` |
| SSDEEP | `98304:fPKyV/fP4Kqg79hZyKpRtoyLZ957xCa4bbS7kBHdXT6FiMXP4SmVodVg88pTKw0q:fJ/m5sAvCge` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_5ee2f468
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ee2f468fac76514a39aac80f78a48a36a3a6585460017bfccca54e4afeb13c2"
    family = "unknown"
    file_name = "ue"
    file_type = "exe"
    first_seen = "2026-08-14 19:28:40"
  condition:
    hash.sha256(0, filesize) == "5ee2f468fac76514a39aac80f78a48a36a3a6585460017bfccca54e4afeb13c2"
}
```

### Sample 81: `9ccef67ad0da073d`

| Field | Value |
|---|---|
| SHA-256 | `9ccef67ad0da073d31a8d5e3b5de18858fe8995c2ea1ebd06be65bbf4f094327` |
| Family label | `Mirai` |
| File name | `data_powerpc` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d20ba61e504f7c7373149d28f1cf705b` |
| SHA-1 | `a099675a0704485d2358a038eef9d751eee04e1e` |
| SHA-256 | `9ccef67ad0da073d31a8d5e3b5de18858fe8995c2ea1ebd06be65bbf4f094327` |
| SHA3-384 | `5c92be873b59206f0ee9e7a5d14a27ebc81ee020c27efafd3b1199d9a91d2e4236354338b941807bfcc827af5135d0d1` |
| TLSH | `T17D443B02771D0F43E2A32DF0373B17E197AEADA114E9E584B50EBEC652B1D721189ACD` |
| SSDEEP | `6144:XCjqXUtRrcO/Xok9A/ySmCaolUg3Ibb8k2wwOOqBZzRu/9Cvt:XCjqktZKKvXScRS9Cvt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_9ccef67a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccef67ad0da073d31a8d5e3b5de18858fe8995c2ea1ebd06be65bbf4f094327"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:43"
  condition:
    hash.sha256(0, filesize) == "9ccef67ad0da073d31a8d5e3b5de18858fe8995c2ea1ebd06be65bbf4f094327"
}
```

### Sample 82: `56e5fa7e2166605a`

| Field | Value |
|---|---|
| SHA-256 | `56e5fa7e2166605afbebfdd75225c7ee967c6b90f24b8fb467e3344b3140bf8a` |
| Family label | `Mirai` |
| File name | `data_x86` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ff01cf12ce14ca2baf33343fb16cd9c` |
| SHA-1 | `cb6019e9b43e8ddc7b9189e14720f410b6cdd6c0` |
| SHA-256 | `56e5fa7e2166605afbebfdd75225c7ee967c6b90f24b8fb467e3344b3140bf8a` |
| SHA3-384 | `ec694f9b1b45eeb819ac186061fdb8abbc05346c36e0eba43b4e2b51bcec7ee371f6e2fbaebc298f2d22897cc107dee8` |
| TLSH | `T125357C9DE3C7D4F1F26341F1021ED7B65534A12A9023FAF6EF4A2A6674323512F1A31A` |
| TELFHASH | `t1c9229db3297969ecbbf08821825f3610de2ae13b25a0347615f36590f7b3e035a35c79` |
| SSDEEP | `24576:a5uzPEskVs0v+FJh8WhXHdj+y02DGI64OGEaZWi4:2gh8WhXHwy03zyZ8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_56e5fa7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e5fa7e2166605afbebfdd75225c7ee967c6b90f24b8fb467e3344b3140bf8a"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:41"
  condition:
    hash.sha256(0, filesize) == "56e5fa7e2166605afbebfdd75225c7ee967c6b90f24b8fb467e3344b3140bf8a"
}
```

### Sample 83: `06cb82aed522086b`

| Field | Value |
|---|---|
| SHA-256 | `06cb82aed522086b5e0d6c138d9f402b2f8df755145072aa1aebf0ea34fc050f` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be19ae35832cf2b3e3020f5a935241c9` |
| SHA-1 | `cc0efc57295971cd0346c45f36996c89d294396c` |
| SHA-256 | `06cb82aed522086b5e0d6c138d9f402b2f8df755145072aa1aebf0ea34fc050f` |
| SHA3-384 | `1bc878cd8f5bea1b718967516899c3df2794b11e9b590dca3fb16380d58d6643f9b60ad920bc426f945f380fcd2caa98` |
| TLSH | `T1E7559F07B7B374BEC093C535879BD662AA32B02501122E7F65C4DA343E17EA45F1EB62` |
| TELFHASH | `t1ea32430e5b2287577d6184c867a9abd32d07850b8b9d8be48de48b0fc6740b7fd128dd` |
| SSDEEP | `24576:sezUC5Dt7P/Rf854sIkPr5m36mCROE7WBppu6td4YOq5uK+hhEZncGmpj:JUCX/Rfa4sIkjQJJDtd4YMESj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_06cb82ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06cb82aed522086b5e0d6c138d9f402b2f8df755145072aa1aebf0ea34fc050f"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:40"
  condition:
    hash.sha256(0, filesize) == "06cb82aed522086b5e0d6c138d9f402b2f8df755145072aa1aebf0ea34fc050f"
}
```

### Sample 84: `e4ebc4f617407f97`

| Field | Value |
|---|---|
| SHA-256 | `e4ebc4f617407f97ad0e7208014c559dc7b9418b48ae320aaf6f3f24027fdbbd` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d237d682eb459a7dad4c7eb7c059e15` |
| SHA-1 | `c4b3c843dc23afd74c7b90f648f7f51d5654e854` |
| SHA-256 | `e4ebc4f617407f97ad0e7208014c559dc7b9418b48ae320aaf6f3f24027fdbbd` |
| SHA3-384 | `c1430023847f9c160db1b76eea1df178712c69c6b67adc17616b5d61008bc939b57c0e7a123b59dc4c08ccdb054ae237` |
| TLSH | `T1FB343B65BD41DF93C6C12AFBFBAE824837132B7DD1EE3102E9146F61239B8960E36541` |
| TELFHASH | `t1cf317565c7d109e4f3f14009521eb43b1aed385e3f122c91a6d97a8f8d539d27061e3a` |
| SSDEEP | `6144:zHz/L137N/j6bCZ4W18co0NWTlpknvnFrUWFs7ET102fsZ1s/:zT/LD+W1hgTlpknvnhUcs7yVsZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_e4ebc4f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4ebc4f617407f97ad0e7208014c559dc7b9418b48ae320aaf6f3f24027fdbbd"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:39"
  condition:
    hash.sha256(0, filesize) == "e4ebc4f617407f97ad0e7208014c559dc7b9418b48ae320aaf6f3f24027fdbbd"
}
```

### Sample 85: `253f87d887637ca9`

| Field | Value |
|---|---|
| SHA-256 | `253f87d887637ca92d57113b189992ceb81507ea4f4e72cc18f64ed4600a6fb1` |
| Family label | `Mirai` |
| File name | `data_arm6` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c74218f8b32abed9e84cffbd02aa9ac8` |
| SHA-1 | `5e9f2ea570fa07791d53f3d9493fab2c5097a09a` |
| SHA-256 | `253f87d887637ca92d57113b189992ceb81507ea4f4e72cc18f64ed4600a6fb1` |
| SHA3-384 | `88dea9aa8a84f19de7474fba5f7d49cef7f52ca5ec6b3c56c9b5b786e7bb02e8bd5bf75ba040db38a6498cfb7ef6e321` |
| TLSH | `T186442C66E941DB92D1C116BEFF6EC24933132F78E3EE7202DD145F60678A89A0E7B501` |
| TELFHASH | `t148e0e57406aa86fa92f08585417e2b5a940c7cae2b443c56c4dd1e8c4667fc534d2c29` |
| SSDEEP | `6144:a4F1CvF4SvwOWZlimhbUh/aB4VWUTScS6zZ4dkarTBijD4vW:jQvF4SAliYNBhUTScS6zukav4jD4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_253f87d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "253f87d887637ca92d57113b189992ceb81507ea4f4e72cc18f64ed4600a6fb1"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:38"
  condition:
    hash.sha256(0, filesize) == "253f87d887637ca92d57113b189992ceb81507ea4f4e72cc18f64ed4600a6fb1"
}
```

### Sample 86: `03ad6e6970a3a4e0`

| Field | Value |
|---|---|
| SHA-256 | `03ad6e6970a3a4e00d40b03068b50619f4f51360e4d9d845433215c262f97489` |
| Family label | `Mirai` |
| File name | `data_aarch64` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d95d6e483d4d0728120deacb88f2e309` |
| SHA-1 | `53757e0db42f4bcc16150e7de57ae18b3dbf9fe8` |
| SHA-256 | `03ad6e6970a3a4e00d40b03068b50619f4f51360e4d9d845433215c262f97489` |
| SHA3-384 | `00860377f21a2346a971f0947abc687b21668683c18222fb3eeed1a9f0202dddc52fc7ee6fec693f3293634b1784a4f0` |
| TLSH | `T1A3057D58FE8E3C52D2C7F27C9E4DC7E1722B7595D26391A23A82024CD5CAAE8CBF1511` |
| SSDEEP | `12288:XDyu/gob3EcNyj/1dDoanXMjpF6iKD3Ho/hWtHBPuxmdVnoFoTDK4w5X7toSgS:XDH/J3EJj/LoanRxI/hWt9LQ+DuuF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_03ad6e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03ad6e6970a3a4e00d40b03068b50619f4f51360e4d9d845433215c262f97489"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:36"
  condition:
    hash.sha256(0, filesize) == "03ad6e6970a3a4e00d40b03068b50619f4f51360e4d9d845433215c262f97489"
}
```

### Sample 87: `980245b5b8929338`

| Field | Value |
|---|---|
| SHA-256 | `980245b5b8929338e63ff710d262859b157cf72e0fb7c89e28913cc48b57dff4` |
| Family label | `Mirai` |
| File name | `data_arm5` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd928b4cf32a4b143b8c137e04dafc35` |
| SHA-1 | `93723972551180eeca508fa4b69c66f38029275b` |
| SHA-256 | `980245b5b8929338e63ff710d262859b157cf72e0fb7c89e28913cc48b57dff4` |
| SHA3-384 | `7efa6774ad432470c7f77143668779e2fe8f24f34bde4804185910fc9d98e8be62f3d1a90bbb388774b5b517ebcf731b` |
| TLSH | `T16C343B51BD41DF93C6C12AFBFBAE824837132B7DD6EE7102E9146F21279B8960E36501` |
| TELFHASH | `t1013124b1cbe40db853e1405860adb01e15ad31a87b5238c3967dbd8e9983582705af3d` |
| SSDEEP | `6144:KRtm6dW25vIPkXkBTZFuLk7GW22LYuT4ENRHMwE3px/:K7mODcruLk7GW2EsEXswE3p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_980245b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "980245b5b8929338e63ff710d262859b157cf72e0fb7c89e28913cc48b57dff4"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:35"
  condition:
    hash.sha256(0, filesize) == "980245b5b8929338e63ff710d262859b157cf72e0fb7c89e28913cc48b57dff4"
}
```

### Sample 88: `e6ef1f96ef026f23`

| Field | Value |
|---|---|
| SHA-256 | `e6ef1f96ef026f2347849fc330a2659246a39a07bebc4560eb6a355142b98c5d` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-08-14 19:17:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cfb410e267ba2b91bd5bb3bd10800f9` |
| SHA-1 | `fc8fd72665ea9ed30812688e67a26a48a4def5ff` |
| SHA-256 | `e6ef1f96ef026f2347849fc330a2659246a39a07bebc4560eb6a355142b98c5d` |
| SHA3-384 | `7ae06654b9152d5e961d77b7fcd7fff990f47ab71ec0b4b500d1938de89fa5242f71b62298d62e7ec3171bd4ce620e93` |
| TLSH | `T17E442B66E9419B91D1C12AFEFF6E824933172F78E3ED7102DD146F6067CA88A0E7B501` |
| TELFHASH | `t1a3418668836058c9d3f49065d0fd72215ece34d67f242087266e3e8e4a46f4070b4c3f` |
| SSDEEP | `6144:fQhoUNoKUR2ld9Skblab7bunYpETWywG0Z8ObaEF9vtGY1LEHFf+Niv0S:jsoKURHkbebXETWywG0+ObaEXvtGY1LM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_e6ef1f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6ef1f96ef026f2347849fc330a2659246a39a07bebc4560eb6a355142b98c5d"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:34"
  condition:
    hash.sha256(0, filesize) == "e6ef1f96ef026f2347849fc330a2659246a39a07bebc4560eb6a355142b98c5d"
}
```

### Sample 89: `d4aaf92e411b242f`

| Field | Value |
|---|---|
| SHA-256 | `d4aaf92e411b242f454647d7a6d1b3657a4699e419b273e7e4b63ce4d2cccb3c` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-14 19:17:28` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84412c10b460870f3f9a5db8df5c4fb1` |
| SHA-1 | `40ee71fb1e584d320db1dcbc71e8b00a2b1b0cac` |
| SHA-256 | `d4aaf92e411b242f454647d7a6d1b3657a4699e419b273e7e4b63ce4d2cccb3c` |
| SHA3-384 | `26608fc8ffb101ff672dd03055730deeb68516e10370650fc0eea38e2667910c703f9a5b243ceaa377f4b974f929aca7` |
| IMPHASH | `8308f72a4cb5fd67d7f3ce32fdc32584` |
| TLSH | `T1BA464C05BA6B94ACD15BC47483068A639E2170DF1B36BAFF018486783F6ABF15B3D714` |
| SSDEEP | `98304:ejblWFqoOFYQlOdda0WH8JvwvRhCYevK:CGG/` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_089_d4aaf92e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4aaf92e411b242f454647d7a6d1b3657a4699e419b273e7e4b63ce4d2cccb3c"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 19:17:28"
  condition:
    hash.sha256(0, filesize) == "d4aaf92e411b242f454647d7a6d1b3657a4699e419b273e7e4b63ce4d2cccb3c"
}
```

### Sample 90: `8810fadecf4f25d2`

| Field | Value |
|---|---|
| SHA-256 | `8810fadecf4f25d249dcc33abb215c5d3c072ba11a86815efda9f51874cd1e4b` |
| Family label | `Mirai` |
| File name | `data_mips` |
| File type | `elf` |
| First seen | `2026-08-14 19:15:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17a31b1d0f189a2a5915ff3d092e5e71` |
| SHA-1 | `87ad93bceb6999fe1fc883f234e9e3f1905a9b3b` |
| SHA-256 | `8810fadecf4f25d249dcc33abb215c5d3c072ba11a86815efda9f51874cd1e4b` |
| SHA3-384 | `54ffda56e4ac21be0e0cd0c5e05d9a730a1bf7c84476a35b5074d40077f9d9901c99279127b4f1cf6d799fcbd780290b` |
| TLSH | `T1AB74B50A6E328F7DF27587708BF34E20E76D73D616E1D684E1ACD5150E2068E641FBA8` |
| TELFHASH | `t16081aa992d7407b4aa44994c45dcfe258da728ef3e490c33db61e85ee71bb835e20c1d` |
| SSDEEP | `6144:SiB26nBgn/crq24pAitU4KxJFgXb+9jV8wE8QsoGOgSrpu615f+URDjH:Sir9AtVXsYplf1DjH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_8810fade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8810fadecf4f25d249dcc33abb215c5d3c072ba11a86815efda9f51874cd1e4b"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-14 19:15:18"
  condition:
    hash.sha256(0, filesize) == "8810fadecf4f25d249dcc33abb215c5d3c072ba11a86815efda9f51874cd1e4b"
}
```

### Sample 91: `7dc5b78098d56c3e`

| Field | Value |
|---|---|
| SHA-256 | `7dc5b78098d56c3efb6ed453be5fc55a117544711973837a7a6529b20b609061` |
| Family label | `Mirai` |
| File name | `data_mipsel` |
| File type | `elf` |
| First seen | `2026-08-14 19:15:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c5f4095931d54d58f76a16ae9b503a4` |
| SHA-1 | `9f490aa9c612b6d39be199ebd18f27fc9e95152e` |
| SHA-256 | `7dc5b78098d56c3efb6ed453be5fc55a117544711973837a7a6529b20b609061` |
| SHA3-384 | `2bca48420bcbf1685fe2b928de172ba7373effae9b75a4d16eb7404750edeac5db6345676a051b0c99a4a95864fe4531` |
| TLSH | `T1B274F80A6F550EB7D86BDD3706FA0B1238CCB85721A93B357078ED14B90A54B4AE3C78` |
| SSDEEP | `6144:RkhgKH+t+t1WEV3+Qeu41n4fMCcf7D9yoJ:Ch5HsREVOau4PU7D9yo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_7dc5b780
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc5b78098d56c3efb6ed453be5fc55a117544711973837a7a6529b20b609061"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-14 19:15:16"
  condition:
    hash.sha256(0, filesize) == "7dc5b78098d56c3efb6ed453be5fc55a117544711973837a7a6529b20b609061"
}
```

### Sample 92: `d5e645ff86350735`

| Field | Value |
|---|---|
| SHA-256 | `d5e645ff8635073533fed23a1db7a64e8391205c822820352add8e2b58aa4319` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-14 19:08:43` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb2babebcecd7bf49a4627b06c672f63` |
| SHA-256 | `d5e645ff8635073533fed23a1db7a64e8391205c822820352add8e2b58aa4319` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_d5e645ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5e645ff8635073533fed23a1db7a64e8391205c822820352add8e2b58aa4319"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 19:08:43"
  condition:
    hash.sha256(0, filesize) == "d5e645ff8635073533fed23a1db7a64e8391205c822820352add8e2b58aa4319"
}
```

### Sample 93: `51b72c4f307600f3`

| Field | Value |
|---|---|
| SHA-256 | `51b72c4f307600f39077630b63cf3748b2db88c66ab0ea2c48c056af14a50c5d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-14 19:08:34` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38f6985b5b2c44fdee00f8cd97c880a4` |
| SHA-256 | `51b72c4f307600f39077630b63cf3748b2db88c66ab0ea2c48c056af14a50c5d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_51b72c4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51b72c4f307600f39077630b63cf3748b2db88c66ab0ea2c48c056af14a50c5d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 19:08:34"
  condition:
    hash.sha256(0, filesize) == "51b72c4f307600f39077630b63cf3748b2db88c66ab0ea2c48c056af14a50c5d"
}
```

### Sample 94: `33211c0e7a7b9545`

| Field | Value |
|---|---|
| SHA-256 | `33211c0e7a7b9545c13addcd452b68ab0f72b2d5fad857a7a3dd75c34a3fff09` |
| Family label | `njrat` |
| File name | `F168APP.exe` |
| File type | `exe` |
| First seen | `2026-08-14 18:53:57` |
| Reporter | `anonymous` |
| Tags | `exe, njrat, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04d9e5ad4e2c94a28a57dcb056cd87ca` |
| SHA-1 | `b2bc67eecaee87f1eff6b0f1e750fda51fa08d46` |
| SHA-256 | `33211c0e7a7b9545c13addcd452b68ab0f72b2d5fad857a7a3dd75c34a3fff09` |
| SHA3-384 | `56d2de4fa9095e4141f5fd7177f7e85516b28db60e9dbac6d7f11782668ec65565d626651b5fd9b99dc4c61fffb0a03c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10BC22A0833E8C672D1FE4ABA883385009779E55B9923D75A5FC490AE29737CD8B18FD4` |
| SSDEEP | `384:GTdv2D9YfxWceOsVa/KFHbhMH9qbuUsUbQxnCJfJBndnjJ0Kw:0dvhi1VDHFiIbKBiBnNw` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_094_33211c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33211c0e7a7b9545c13addcd452b68ab0f72b2d5fad857a7a3dd75c34a3fff09"
    family = "njrat"
    file_name = "F168APP.exe"
    file_type = "exe"
    first_seen = "2026-08-14 18:53:57"
  condition:
    hash.sha256(0, filesize) == "33211c0e7a7b9545c13addcd452b68ab0f72b2d5fad857a7a3dd75c34a3fff09"
}
```

### Sample 95: `747f8f2c557f5ca2`

| Field | Value |
|---|---|
| SHA-256 | `747f8f2c557f5ca2ff3ac797ffe4df4b2e042a747e5d728060c49bda2466e5c0` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 18:53:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db622a86e81de720fc5d1b881ce55504` |
| SHA-1 | `657317c53092ec36f19c177f86bb7812350f45c5` |
| SHA-256 | `747f8f2c557f5ca2ff3ac797ffe4df4b2e042a747e5d728060c49bda2466e5c0` |
| SHA3-384 | `8a4734f1243b36517db9ca1d5ffb1643f7588f3047a2f6fd3adc4b2ee38441546ea35d50d3c9d0e3f58dab7342052123` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1E2E6330CDBE006A6FDA3D0B9E9E229B392A97CA54775C5DB13D803537E132E04D3D626` |
| SSDEEP | `393216:D0TlPOxuNMx/P3ZHh8DXMCHWUjCcuI3/PGTAI:DnuNMxp+DXMb8/H/O7` |
| ICON-DHASH | `38dcf8f8fcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_747f8f2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "747f8f2c557f5ca2ff3ac797ffe4df4b2e042a747e5d728060c49bda2466e5c0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 18:53:29"
  condition:
    hash.sha256(0, filesize) == "747f8f2c557f5ca2ff3ac797ffe4df4b2e042a747e5d728060c49bda2466e5c0"
}
```

### Sample 96: `d7f44f8336a745e0`

| Field | Value |
|---|---|
| SHA-256 | `d7f44f8336a745e0b074faa039203126b26ce7e46d89301fc9233fe2e193d6cf` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 17:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ff3a25ac87006a7919ede44ed365493` |
| SHA-1 | `3d0b8061e59109ef8ef6df0b3f83b79c4dd54076` |
| SHA-256 | `d7f44f8336a745e0b074faa039203126b26ce7e46d89301fc9233fe2e193d6cf` |
| SHA3-384 | `dc036f66313ddfa835dd6e12132a1a8df802afa2cd0d6ba2d7ff078dfa27971048b5b9bdc619d4612bd018fd13821df5` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T177E63309EEE066BAE563813CDAF21095F435B4621B69C5DB57AC43A16D032E01E3CB7B` |
| SSDEEP | `393216:fJXDmvUHFTWkrcKmsXMCHWUjHcuI3/PGTAI:fZDm8HBo8XMb88H/O7` |
| ICON-DHASH | `71f0e8e8e8e8f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_d7f44f83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7f44f8336a745e0b074faa039203126b26ce7e46d89301fc9233fe2e193d6cf"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 17:52:32"
  condition:
    hash.sha256(0, filesize) == "d7f44f8336a745e0b074faa039203126b26ce7e46d89301fc9233fe2e193d6cf"
}
```

### Sample 97: `00180c06765fed73`

| Field | Value |
|---|---|
| SHA-256 | `00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2` |
| Family label | `AsyncRAT` |
| File name | `00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2` |
| File type | `exe` |
| First seen | `2026-08-14 17:40:05` |
| Reporter | `johnk3r` |
| Tags | `AsyncRAT, exe, server2026-pro` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d26392c3b5219b0203db083a1168d1d6` |
| SHA-1 | `da456e6132f0f26353026d43e0e1fe2b9b021edb` |
| SHA-256 | `00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2` |
| SHA3-384 | `eb72979d8112a06e6c4e8107402e011624c8abf5bd666fcf4be84ef4adb060dd9693774009dcdbbd1166bdff8750432c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18293B5863799523BF3ABFE705DD42CD3856EEA736C86E51A04B342560E016C0EEC7879` |
| SSDEEP | `1536:2NGsGeplXXsJ7+rLmtMnn+bGWssDY/os3UFj8lQZAkmX52KEENXiY3gSbxsciRDH:2NGsGeplXXsJ7+rLmtMnn+bGWssDY/oZ` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_097_00180c06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2"
    family = "AsyncRAT"
    file_name = "00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2"
    file_type = "exe"
    first_seen = "2026-08-14 17:40:05"
  condition:
    hash.sha256(0, filesize) == "00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2"
}
```

### Sample 98: `439d40c57e8d7bb7`

| Field | Value |
|---|---|
| SHA-256 | `439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3` |
| Family label | `unknown` |
| File name | `439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3` |
| File type | `dll` |
| First seen | `2026-08-14 17:38:03` |
| Reporter | `johnk3r` |
| Tags | `dll, server2026-pro` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ebf6bbb2ea78ae42477514ed8fdf02e` |
| SHA-1 | `3fabc3ed160d273ab22b03d24327bdc5fe9c9e34` |
| SHA-256 | `439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3` |
| SHA3-384 | `eb393bcef5c2d29fed90ce217df14012315d0700b7144923f5259ec2b29c2e779e3da917e3ad9509a337a96096310f9f` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T1ACB1730A57DD0933E8FE077468F313A32634FA519E968B9F08C0212D7EA67545A327E1` |
| SSDEEP | `48:6kBBlj8n2wZHJTpIishfldMjRIMD6VOOFCGa81JfhgcMsgKllLXts1ulfa3zq:piZpTpIFzdMjya6VO0CGa6gz0llz9NK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_439d40c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3"
    family = "unknown"
    file_name = "439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3"
    file_type = "dll"
    first_seen = "2026-08-14 17:38:03"
  condition:
    hash.sha256(0, filesize) == "439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3"
}
```

### Sample 99: `06a98cd523b8d3bd`

| Field | Value |
|---|---|
| SHA-256 | `06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85` |
| Family label | `AsyncRAT` |
| File name | `06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85.js` |
| File type | `js` |
| First seen | `2026-08-14 17:36:43` |
| Reporter | `johnk3r` |
| Tags | `js, server2026-pro` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1a9b719ec981b60d7a50eca037968e3` |
| SHA-1 | `0356ca9135f95c5e17aef6052d9329a2d6b8508a` |
| SHA-256 | `06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85` |
| SHA3-384 | `9fcf2afd802f2e37a96117169024a049d0372c3c98fd8c1652ba03db80ed74704b1e56305098417b9e07ebf57a616150` |
| TLSH | `T115E4E9A16A4030BB9767542B819DA9FE83717F330F13284B927416D61B3A7C3BE5294F` |
| SSDEEP | `12288:rlGJg/ZrAEeWd2n7uozan4hVKo5d5TvTiDjE:Sg/ZheTnnasPniHE` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_099_06a98cd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85"
    family = "AsyncRAT"
    file_name = "06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85.js"
    file_type = "js"
    first_seen = "2026-08-14 17:36:43"
  condition:
    hash.sha256(0, filesize) == "06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85"
}
```

### Sample 100: `190c466cd581085a`

| Field | Value |
|---|---|
| SHA-256 | `190c466cd581085a3037192247db1b0cbfc67fb92fe3cead3e5f0c4683f8f4ef` |
| Family label | `RemoteX` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-14 17:18:24` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, RemoteX` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `386805bffc1ad4bf781e353acf3581b4` |
| SHA-1 | `15ebce25142f0c9c14728be244469f703d1340f0` |
| SHA-256 | `190c466cd581085a3037192247db1b0cbfc67fb92fe3cead3e5f0c4683f8f4ef` |
| SHA3-384 | `c2552c828c6f0617ae090d2e2d1b42914dd90a297ac7ba935a9edf56f1f49146d958f86b6b0eb2f5c00e534b6da202b5` |
| IMPHASH | `bf3d0d0ac28688e113006e8b183acf31` |
| TLSH | `T1F1574A47F86109E5D0AED175CA269213BB713C994F3063D72B60F7642F36BE0AA7A704` |
| SSDEEP | `196608:SbonrNJ2tNGEc4yH1uYUJB0HXZ97MM6DJMrEHrcBdoJhPa361Vf:ScrNJ2294yVuYSu7Mx1MrELcBdoHa3` |

#### Technical Assessment

- The sample is tracked as `RemoteX` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemoteX_100_190c466c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "190c466cd581085a3037192247db1b0cbfc67fb92fe3cead3e5f0c4683f8f4ef"
    family = "RemoteX"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 17:18:24"
  condition:
    hash.sha256(0, filesize) == "190c466cd581085a3037192247db1b0cbfc67fb92fe3cead3e5f0c4683f8f4ef"
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
 * Generated: 2026-08-15T01:52:40.391434+00:00
 */

rule MalwareBazaar_unknown_001_064726f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "064726f32e709694520801994c297551e07782fb3d4d9e5c8a44cb6792d8dd02"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 01:36:45"
  condition:
    hash.sha256(0, filesize) == "064726f32e709694520801994c297551e07782fb3d4d9e5c8a44cb6792d8dd02"
}

rule MalwareBazaar_unknown_002_2187038e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f"
    family = "unknown"
    file_name = "2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f.bin"
    file_type = "exe"
    first_seen = "2026-08-15 01:23:52"
  condition:
    hash.sha256(0, filesize) == "2187038e66f6ebaeec12dd27ef3c423de821294ccd93e070ac13852a68df299f"
}

rule MalwareBazaar_unknown_003_8edbfc69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea"
    family = "unknown"
    file_name = "8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea.elf"
    file_type = "elf"
    first_seen = "2026-08-15 01:19:34"
  condition:
    hash.sha256(0, filesize) == "8edbfc6979fddbb9e65748ad45293732de87d4bb1e6437412f3335258f1045ea"
}

rule MalwareBazaar_unknown_004_839b184f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd"
    family = "unknown"
    file_name = "839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd.bin"
    file_type = "zip"
    first_seen = "2026-08-15 01:14:33"
  condition:
    hash.sha256(0, filesize) == "839b184f7816c68f7aaf816f1b329a363ad080670447ed2dbcfa0a85143cabbd"
}

rule MalwareBazaar_ConnectWise_005_5bd490db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bd490dbc4b0aa47cfaba73ba2394edecbea4f0d196158512a85c2ed5521d4c5"
    family = "ConnectWise"
    file_name = "Adobe_Acrobat_Update.vbs"
    file_type = "vbs"
    first_seen = "2026-08-15 00:58:29"
  condition:
    hash.sha256(0, filesize) == "5bd490dbc4b0aa47cfaba73ba2394edecbea4f0d196158512a85c2ed5521d4c5"
}

rule MalwareBazaar_unknown_006_35491352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35491352181d7598270320d15f331f250c848f94b09ce008d78d901b2b5950e0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-15 00:53:35"
  condition:
    hash.sha256(0, filesize) == "35491352181d7598270320d15f331f250c848f94b09ce008d78d901b2b5950e0"
}

rule MalwareBazaar_unknown_007_0775c10d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae"
    family = "unknown"
    file_name = "0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae.bin"
    file_type = "exe"
    first_seen = "2026-08-15 00:53:34"
  condition:
    hash.sha256(0, filesize) == "0775c10d939f7b0e7296492cf754fc34518e6fd66c86d3af81dca7e844f6ceae"
}

rule MalwareBazaar_unknown_008_87a180e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87a180e1e975b060f55963476f966f3c9afe8e3794cc66ed1702ea909898d663"
    family = "unknown"
    file_name = "540453966.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:50:59"
  condition:
    hash.sha256(0, filesize) == "87a180e1e975b060f55963476f966f3c9afe8e3794cc66ed1702ea909898d663"
}

rule MalwareBazaar_unknown_009_4f8b3ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f8b3ce56a567f4d1f5a3e4ef0fedcdfad707bfc1b4234397da600f8e2e32316"
    family = "unknown"
    file_name = "Pro Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:34:42"
  condition:
    hash.sha256(0, filesize) == "4f8b3ce56a567f4d1f5a3e4ef0fedcdfad707bfc1b4234397da600f8e2e32316"
}

rule MalwareBazaar_unknown_010_57478a0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57478a0f3dcf4df1c96dbb3cd9aa3b255814bd3a4185bf90ba768eb28b471797"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:32:55"
  condition:
    hash.sha256(0, filesize) == "57478a0f3dcf4df1c96dbb3cd9aa3b255814bd3a4185bf90ba768eb28b471797"
}

rule MalwareBazaar_unknown_011_c9698c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9698c118c2ba58fb2c7944354687333bd4f0d58ce5b6710920cdfa682bc9944"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:31:49"
  condition:
    hash.sha256(0, filesize) == "c9698c118c2ba58fb2c7944354687333bd4f0d58ce5b6710920cdfa682bc9944"
}

rule MalwareBazaar_unknown_012_514fa778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "514fa7786356f49ad0e1164fec6fcfb3c2759db9c069beac2f89baa804f7d5fe"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:30:56"
  condition:
    hash.sha256(0, filesize) == "514fa7786356f49ad0e1164fec6fcfb3c2759db9c069beac2f89baa804f7d5fe"
}

rule MalwareBazaar_unknown_013_f4a8e430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4a8e4307944c6decec264820f699e4e4adee02fc71da530ad862dee959528cb"
    family = "unknown"
    file_name = "LauncherV33281.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:29:30"
  condition:
    hash.sha256(0, filesize) == "f4a8e4307944c6decec264820f699e4e4adee02fc71da530ad862dee959528cb"
}

rule MalwareBazaar_unknown_014_80cd87cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80cd87cbf731d14baa0698a22a0ebf8db7b305a740d0015d985e94b6b197a2f3"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-15 00:28:59"
  condition:
    hash.sha256(0, filesize) == "80cd87cbf731d14baa0698a22a0ebf8db7b305a740d0015d985e94b6b197a2f3"
}

rule MalwareBazaar_unknown_015_7e52031a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e52031a2ef388824fd6e39f25b626b09be13e33a79d291a4790affdb9b93593"
    family = "unknown"
    file_name = "FLStudio2025_v256_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:28:10"
  condition:
    hash.sha256(0, filesize) == "7e52031a2ef388824fd6e39f25b626b09be13e33a79d291a4790affdb9b93593"
}

rule MalwareBazaar_unknown_016_6702d4f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6702d4f508ebf248a56bb2d14b1afdc8557398b3b94c25a6d23eb61533647373"
    family = "unknown"
    file_name = "atom.dll"
    file_type = "exe"
    first_seen = "2026-08-15 00:25:56"
  condition:
    hash.sha256(0, filesize) == "6702d4f508ebf248a56bb2d14b1afdc8557398b3b94c25a6d23eb61533647373"
}

rule MalwareBazaar_unknown_017_ad1f1c29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad1f1c29707bba2a41e9d964abb63ff0dc764ea98c3e2a1e38a39dd2c7bcfd6b"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:23:17"
  condition:
    hash.sha256(0, filesize) == "ad1f1c29707bba2a41e9d964abb63ff0dc764ea98c3e2a1e38a39dd2c7bcfd6b"
}

rule MalwareBazaar_unknown_018_b60ad1ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c"
    family = "unknown"
    file_name = "b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c.bin"
    file_type = "exe"
    first_seen = "2026-08-15 00:23:17"
  condition:
    hash.sha256(0, filesize) == "b60ad1eee8bc9dcd7c721e381a095973c1aab6eb66f594663548f61e79b5091c"
}

rule MalwareBazaar_unknown_019_5cc44ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cc44ec9af3b258dc4cd4fddccfa03550e8f5d3aa57fe78eb9c0805ed0850182"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:21:55"
  condition:
    hash.sha256(0, filesize) == "5cc44ec9af3b258dc4cd4fddccfa03550e8f5d3aa57fe78eb9c0805ed0850182"
}

rule MalwareBazaar_unknown_020_2ceeac4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ceeac4dd38579e87936343e2819492ac88dd27d489aa72ef5c622e772f9bf0c"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-15 00:12:14"
  condition:
    hash.sha256(0, filesize) == "2ceeac4dd38579e87936343e2819492ac88dd27d489aa72ef5c622e772f9bf0c"
}

rule MalwareBazaar_Mirai_021_709716d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "709716d13a356e2ef12dedd3313eeac002dcab955c50406bd2dfe38fab5a1c1a"
    family = "Mirai"
    file_name = "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:05:49"
  condition:
    hash.sha256(0, filesize) == "709716d13a356e2ef12dedd3313eeac002dcab955c50406bd2dfe38fab5a1c1a"
}

rule MalwareBazaar_Mirai_022_df4888a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df4888a7ef78e32e2819fe5af82369ecc85b681e5648837224fd44d413e267df"
    family = "Mirai"
    file_name = "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:05:46"
  condition:
    hash.sha256(0, filesize) == "df4888a7ef78e32e2819fe5af82369ecc85b681e5648837224fd44d413e267df"
}

rule MalwareBazaar_Mirai_023_5fa395bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d"
    family = "Mirai"
    file_name = "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:04:33"
  condition:
    hash.sha256(0, filesize) == "5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d"
}

rule MalwareBazaar_Mirai_024_e3b410b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39"
    family = "Mirai"
    file_name = "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39.elf"
    file_type = "elf"
    first_seen = "2026-08-15 00:04:29"
  condition:
    hash.sha256(0, filesize) == "e3b410b16785aa991ed02206f3108ae3a5c7d888a181e590bdce09baeb5b8a39"
}

rule MalwareBazaar_Mirai_025_c1466a7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1466a7a1732dfdba03457e094ee8dde9a9ebbaf856a7b66854e7ca8222cf976"
    family = "Mirai"
    file_name = "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97.elf"
    file_type = "elf"
    first_seen = "2026-08-14 23:55:42"
  condition:
    hash.sha256(0, filesize) == "c1466a7a1732dfdba03457e094ee8dde9a9ebbaf856a7b66854e7ca8222cf976"
}

rule MalwareBazaar_Mirai_026_376c342d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97"
    family = "Mirai"
    file_name = "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97.elf"
    file_type = "elf"
    first_seen = "2026-08-14 23:54:46"
  condition:
    hash.sha256(0, filesize) == "376c342dc4261ca7ab791d1830696d3b0401dba1210a4386d8e58f63cbd5aa97"
}

rule MalwareBazaar_unknown_027_1182e436
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1182e436076f313fb9f22b4cf27918570c50d0ec90fc10d6383a1e86448d68d5"
    family = "unknown"
    file_name = "update.exe"
    file_type = "exe"
    first_seen = "2026-08-14 23:52:40"
  condition:
    hash.sha256(0, filesize) == "1182e436076f313fb9f22b4cf27918570c50d0ec90fc10d6383a1e86448d68d5"
}

rule MalwareBazaar_unknown_028_5316c1fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5316c1faefa33328e593d3cf4d54d6e25d7243862d65a67189f76d8b38a682ea"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 23:52:30"
  condition:
    hash.sha256(0, filesize) == "5316c1faefa33328e593d3cf4d54d6e25d7243862d65a67189f76d8b38a682ea"
}

rule MalwareBazaar_unknown_029_cce7a3a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cce7a3a488bbc717325a24528c733b820181feeda1a6c168f297c4a090aa3cb1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 23:39:34"
  condition:
    hash.sha256(0, filesize) == "cce7a3a488bbc717325a24528c733b820181feeda1a6c168f297c4a090aa3cb1"
}

rule MalwareBazaar_unknown_030_59d42ff1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d42ff1cad50cd84342e6ce6beb2896e63d36971b83bc42817bb227db04260f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 23:26:18"
  condition:
    hash.sha256(0, filesize) == "59d42ff1cad50cd84342e6ce6beb2896e63d36971b83bc42817bb227db04260f"
}

rule MalwareBazaar_Mirai_031_7d700aaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f"
    family = "Mirai"
    file_name = "7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f.elf"
    file_type = "elf"
    first_seen = "2026-08-14 22:57:08"
  condition:
    hash.sha256(0, filesize) == "7d700aaf9805bc27c590e66fb12f66200a8082d2f5f075f11fcda2405ba93c9f"
}

rule MalwareBazaar_unknown_032_2b5994f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b5994f3a89f4efb1fc1459059b0b74c4935cb587981caeaae14598582058368"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 22:52:50"
  condition:
    hash.sha256(0, filesize) == "2b5994f3a89f4efb1fc1459059b0b74c4935cb587981caeaae14598582058368"
}

rule MalwareBazaar_Prometei_033_ce2d0bbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112"
    family = "Prometei"
    file_name = "ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112"
    file_type = "elf"
    first_seen = "2026-08-14 22:51:38"
  condition:
    hash.sha256(0, filesize) == "ce2d0bbd100e613b64ec88a3885882d73493f5beb318abf43d8ac5204327e112"
}

rule MalwareBazaar_unknown_034_d44ff00f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d44ff00fe9552510aefbf13c4b986dc094b5aefcd099fd3d7ad6dc816968a50b"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Packed.Themida.21.63687778"
    file_type = "exe"
    first_seen = "2026-08-14 22:47:03"
  condition:
    hash.sha256(0, filesize) == "d44ff00fe9552510aefbf13c4b986dc094b5aefcd099fd3d7ad6dc816968a50b"
}

rule MalwareBazaar_unknown_035_5869e740
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5869e740ee9d36f62ee9e6e01b4deded4970043d6a6cdd792d0beb383b62c842"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Midie.185781.47871582"
    file_type = "exe"
    first_seen = "2026-08-14 22:47:01"
  condition:
    hash.sha256(0, filesize) == "5869e740ee9d36f62ee9e6e01b4deded4970043d6a6cdd792d0beb383b62c842"
}

rule MalwareBazaar_unknown_036_ed6a55a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed6a55a28e22520219c90adeb569c114ab8f01f1e1f2674e06615fe046e7a291"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 21:52:52"
  condition:
    hash.sha256(0, filesize) == "ed6a55a28e22520219c90adeb569c114ab8f01f1e1f2674e06615fe046e7a291"
}

rule MalwareBazaar_unknown_037_48a2b07e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48a2b07e5135769fd31f8fa6ab2ba75ab1e7b3f50b0378ca5eb0f4cd2cd2dc20"
    family = "unknown"
    file_name = "vmvshgsozcauxmsezzpi.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:48:56"
  condition:
    hash.sha256(0, filesize) == "48a2b07e5135769fd31f8fa6ab2ba75ab1e7b3f50b0378ca5eb0f4cd2cd2dc20"
}

rule MalwareBazaar_ValleyRAT_038_aafaddd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aafaddd58c513931655be4a52b11317283b500ef27608a83af45d4e625568d20"
    family = "ValleyRAT"
    file_name = "appinst_up001.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:33:36"
  condition:
    hash.sha256(0, filesize) == "aafaddd58c513931655be4a52b11317283b500ef27608a83af45d4e625568d20"
}

rule MalwareBazaar_unknown_039_ccd2629e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de"
    family = "unknown"
    file_name = "ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:29:46"
  condition:
    hash.sha256(0, filesize) == "ccd2629ecdbaefa655ce6656c94325a8bf91ffa0692b056819698364e0ed69de"
}

rule MalwareBazaar_unknown_040_88bf7101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303"
    family = "unknown"
    file_name = "88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:29:40"
  condition:
    hash.sha256(0, filesize) == "88bf710192a943e7373d337e9acaa566f57ffa2623703d6206a802099fba8303"
}

rule MalwareBazaar_unknown_041_37804820
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3780482094b9322d8869c7c52966a49e7f285c0016525ffffa6d5458231c271f"
    family = "unknown"
    file_name = "vmvshgsozcauxmsezzpi.exe"
    file_type = "exe"
    first_seen = "2026-08-14 21:14:22"
  condition:
    hash.sha256(0, filesize) == "3780482094b9322d8869c7c52966a49e7f285c0016525ffffa6d5458231c271f"
}

rule MalwareBazaar_Mirai_042_d2d39770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d397702d12849d4db154c4470dea306cb88d9c95755a37aafde09e61769781"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-08-14 20:58:41"
  condition:
    hash.sha256(0, filesize) == "d2d397702d12849d4db154c4470dea306cb88d9c95755a37aafde09e61769781"
}

rule MalwareBazaar_unknown_043_9e3e3514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e3e3514cd791e9aeef6e0d4274a46534213b4b30318c24d5bddc287738ca4b6"
    family = "unknown"
    file_name = "my_sss.exe"
    file_type = "exe"
    first_seen = "2026-08-14 20:58:01"
  condition:
    hash.sha256(0, filesize) == "9e3e3514cd791e9aeef6e0d4274a46534213b4b30318c24d5bddc287738ca4b6"
}

rule MalwareBazaar_Mirai_044_e1565729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e156572994d3a6d977ffed757b4ea6723b1e35d2c03db01dfe2f53f1d6d3b848"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-08-14 20:57:52"
  condition:
    hash.sha256(0, filesize) == "e156572994d3a6d977ffed757b4ea6723b1e35d2c03db01dfe2f53f1d6d3b848"
}

rule MalwareBazaar_unknown_045_4840f243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4840f24362fab800677052f41e6075ea8378660a43621d7ab497268c36b322b4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:57:51"
  condition:
    hash.sha256(0, filesize) == "4840f24362fab800677052f41e6075ea8378660a43621d7ab497268c36b322b4"
}

rule MalwareBazaar_unknown_046_1e0a8824
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e0a8824261e3edb36d12fd5ce659cbb3989d4470809d2310cc56cd47da53555"
    family = "unknown"
    file_name = "zxc9.exe"
    file_type = "exe"
    first_seen = "2026-08-14 20:57:48"
  condition:
    hash.sha256(0, filesize) == "1e0a8824261e3edb36d12fd5ce659cbb3989d4470809d2310cc56cd47da53555"
}

rule MalwareBazaar_unknown_047_8daa6c06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8daa6c064b47a03c85bc0eff732da07e0e8966cfc69771e3b9597cad9a155b13"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 20:52:32"
  condition:
    hash.sha256(0, filesize) == "8daa6c064b47a03c85bc0eff732da07e0e8966cfc69771e3b9597cad9a155b13"
}

rule MalwareBazaar_unknown_048_769c5186
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded"
    family = "unknown"
    file_name = "769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded.bin"
    file_type = "exe"
    first_seen = "2026-08-14 20:51:21"
  condition:
    hash.sha256(0, filesize) == "769c5186f40c16fa4e4871bf488301c01e89e3e94f1244f979e1b12b7f244ded"
}

rule MalwareBazaar_unknown_049_1d118a94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e"
    family = "unknown"
    file_name = "1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e.bin"
    file_type = "exe"
    first_seen = "2026-08-14 20:51:19"
  condition:
    hash.sha256(0, filesize) == "1d118a9482bb8f30bb53c18c8441d5aa8b21ee823206c630238edf0f99ec568e"
}

rule MalwareBazaar_unknown_050_f2b7f869
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d"
    family = "unknown"
    file_name = "f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d.bin"
    file_type = "exe"
    first_seen = "2026-08-14 20:51:17"
  condition:
    hash.sha256(0, filesize) == "f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d"
}

rule MalwareBazaar_Mirai_051_a4b5e01c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4b5e01c133b3da9ae56b2d96bc003b0fb8431c2f454f25984428d3c7212c6cc"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-14 20:50:43"
  condition:
    hash.sha256(0, filesize) == "a4b5e01c133b3da9ae56b2d96bc003b0fb8431c2f454f25984428d3c7212c6cc"
}

rule MalwareBazaar_Mirai_052_b8c1f1f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8c1f1f1cf3815c67b4a840c1fc16e05f190717a3cc5288f5307b3af06578da7"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-14 20:49:55"
  condition:
    hash.sha256(0, filesize) == "b8c1f1f1cf3815c67b4a840c1fc16e05f190717a3cc5288f5307b3af06578da7"
}

rule MalwareBazaar_unknown_053_08f41cf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172"
    family = "unknown"
    file_name = "08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172.bin"
    file_type = "zip"
    first_seen = "2026-08-14 20:39:43"
  condition:
    hash.sha256(0, filesize) == "08f41cf391af5b60dadd15d9f615d2fa3da28d5c6e6ce967c9c8037d075e2172"
}

rule MalwareBazaar_unknown_054_41b84dfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92"
    family = "unknown"
    file_name = "41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92.bin"
    file_type = "zip"
    first_seen = "2026-08-14 20:39:39"
  condition:
    hash.sha256(0, filesize) == "41b84dfc97d534cb846d6485968b1c5c2e44d17e5f63161c7c6509886b16bf92"
}

rule MalwareBazaar_Mirai_055_9f9bf79c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f9bf79cde61182ca08d425604c51b9d0913b072f8bfc325693677abbc359260"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-14 20:36:16"
  condition:
    hash.sha256(0, filesize) == "9f9bf79cde61182ca08d425604c51b9d0913b072f8bfc325693677abbc359260"
}

rule MalwareBazaar_Mirai_056_9068808a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9068808aff079079e74325af79f7166dc6da8ff2c008dca4823411e992052288"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-14 20:32:39"
  condition:
    hash.sha256(0, filesize) == "9068808aff079079e74325af79f7166dc6da8ff2c008dca4823411e992052288"
}

rule MalwareBazaar_Mirai_057_896f63d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896f63d1435cd22055e0e9c1d240fb51291d8e870ce4e1df89c2922ffdd713ff"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-14 20:32:22"
  condition:
    hash.sha256(0, filesize) == "896f63d1435cd22055e0e9c1d240fb51291d8e870ce4e1df89c2922ffdd713ff"
}

rule MalwareBazaar_unknown_058_90777182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9077718299112945704be6a44d2f7e927a18e449c33e77dc523673cafbfedd35"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:32:21"
  condition:
    hash.sha256(0, filesize) == "9077718299112945704be6a44d2f7e927a18e449c33e77dc523673cafbfedd35"
}

rule MalwareBazaar_unknown_059_313dbce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "313dbce684c3b044d5d5fd996d21b9af717241b4c413db5e401417147fbd408b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:26:17"
  condition:
    hash.sha256(0, filesize) == "313dbce684c3b044d5d5fd996d21b9af717241b4c413db5e401417147fbd408b"
}

rule MalwareBazaar_unknown_060_548bb9f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548bb9f32f10098578ac482ed67f827aeae36bfb32845dd16556d532ea19fa05"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 20:23:27"
  condition:
    hash.sha256(0, filesize) == "548bb9f32f10098578ac482ed67f827aeae36bfb32845dd16556d532ea19fa05"
}

rule MalwareBazaar_Mirai_061_5c999482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c9994823d70eeaa4c95fa42af69ee5e777510e7cfbdd407ec21205b44979c1b"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-14 20:18:42"
  condition:
    hash.sha256(0, filesize) == "5c9994823d70eeaa4c95fa42af69ee5e777510e7cfbdd407ec21205b44979c1b"
}

rule MalwareBazaar_unknown_062_2d0c8c72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d0c8c72f8d095358ba3237d833ceb20971a6255cab8d76eb3631a016bbcd91c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 20:18:12"
  condition:
    hash.sha256(0, filesize) == "2d0c8c72f8d095358ba3237d833ceb20971a6255cab8d76eb3631a016bbcd91c"
}

rule MalwareBazaar_Mirai_063_b20f7d9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20f7d9fe9143a2cb2650f33f2d63f93f0d03a171da810e42d4a256de4d81bd5"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-14 20:18:01"
  condition:
    hash.sha256(0, filesize) == "b20f7d9fe9143a2cb2650f33f2d63f93f0d03a171da810e42d4a256de4d81bd5"
}

rule MalwareBazaar_unknown_064_ce264702
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce264702b5d9fa27e53da389d15be01cd0efb83713da99824a714a61f71df43a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 20:15:34"
  condition:
    hash.sha256(0, filesize) == "ce264702b5d9fa27e53da389d15be01cd0efb83713da99824a714a61f71df43a"
}

rule MalwareBazaar_unknown_065_5320d565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5320d565de984280aed253f7ba82c3a5f9d6a7be23300e746e10c63f2b583cbd"
    family = "unknown"
    file_name = "ue"
    file_type = "exe"
    first_seen = "2026-08-14 20:12:14"
  condition:
    hash.sha256(0, filesize) == "5320d565de984280aed253f7ba82c3a5f9d6a7be23300e746e10c63f2b583cbd"
}

rule MalwareBazaar_Mirai_066_3ce639bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ce639bc2635ef7a4eb81dbe22a6d3a87c34d65477ac83a420b3480baeffc145"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-08-14 20:11:21"
  condition:
    hash.sha256(0, filesize) == "3ce639bc2635ef7a4eb81dbe22a6d3a87c34d65477ac83a420b3480baeffc145"
}

rule MalwareBazaar_unknown_067_6098837b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6098837b41d4a66b3d5a0137823a9331695775b4e38f86c4ab91b73a9c3eec8c"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-14 20:09:14"
  condition:
    hash.sha256(0, filesize) == "6098837b41d4a66b3d5a0137823a9331695775b4e38f86c4ab91b73a9c3eec8c"
}

rule MalwareBazaar_unknown_068_529dc632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "529dc632c717f0785a23c47db89ce152fdf1e42c7f55def460cc62df64a7778f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 20:09:12"
  condition:
    hash.sha256(0, filesize) == "529dc632c717f0785a23c47db89ce152fdf1e42c7f55def460cc62df64a7778f"
}

rule MalwareBazaar_unknown_069_effad2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "effad2cfdbb44e803001b7108acfad70cb0b42dc324055f275f3d73cf4d148cf"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 20:09:03"
  condition:
    hash.sha256(0, filesize) == "effad2cfdbb44e803001b7108acfad70cb0b42dc324055f275f3d73cf4d148cf"
}

rule MalwareBazaar_Mirai_070_a9ba51f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9ba51f0fde56b9fe59dbaee6a3812631471a8d45b9f90b6aee06db927b86fb7"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-08-14 20:04:39"
  condition:
    hash.sha256(0, filesize) == "a9ba51f0fde56b9fe59dbaee6a3812631471a8d45b9f90b6aee06db927b86fb7"
}

rule MalwareBazaar_Mirai_071_036000ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "036000bac9d3ec067332774b1b8a9b057554d255ff845f801f5d882a5ed9aba5"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-14 20:00:02"
  condition:
    hash.sha256(0, filesize) == "036000bac9d3ec067332774b1b8a9b057554d255ff845f801f5d882a5ed9aba5"
}

rule MalwareBazaar_unknown_072_24e9f686
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8"
    family = "unknown"
    file_name = "24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8.exe"
    file_type = "exe"
    first_seen = "2026-08-14 19:59:41"
  condition:
    hash.sha256(0, filesize) == "24e9f686006278823319425f9e0a7edbb6b431a9758e404d88e2dedb2a182cc8"
}

rule MalwareBazaar_Mirai_073_981525a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981525a1d804038294a0cf24fe434f4f44e82cb93c2e324c398829f0f4e1907c"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-14 19:55:52"
  condition:
    hash.sha256(0, filesize) == "981525a1d804038294a0cf24fe434f4f44e82cb93c2e324c398829f0f4e1907c"
}

rule MalwareBazaar_Mirai_074_7780fb81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7780fb81a5342b747a9796b6ba6a401c0259faad077cf9ca739ef70e14e75c7c"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-14 19:55:17"
  condition:
    hash.sha256(0, filesize) == "7780fb81a5342b747a9796b6ba6a401c0259faad077cf9ca739ef70e14e75c7c"
}

rule MalwareBazaar_unknown_075_26e37807
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e37807d3f5562c48d14452f81b586fd963831f3d185d2e150e0080f9013ec5"
    family = "unknown"
    file_name = "NotaFiscal_1546_AshPin_8755.zip"
    file_type = "zip"
    first_seen = "2026-08-14 19:54:47"
  condition:
    hash.sha256(0, filesize) == "26e37807d3f5562c48d14452f81b586fd963831f3d185d2e150e0080f9013ec5"
}

rule MalwareBazaar_CoinMiner_076_958f41d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3"
    family = "CoinMiner"
    file_name = "958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3.exe"
    file_type = "exe"
    first_seen = "2026-08-14 19:54:36"
  condition:
    hash.sha256(0, filesize) == "958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3"
}

rule MalwareBazaar_unknown_077_dc33f06c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc33f06c86f021af72cc89e1feafa16dad624d43a79242ab738518480a0aef88"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 19:52:30"
  condition:
    hash.sha256(0, filesize) == "dc33f06c86f021af72cc89e1feafa16dad624d43a79242ab738518480a0aef88"
}

rule MalwareBazaar_Mirai_078_f06db00d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f06db00d66ee3be3c536bd1cde95514c852ca08261af889acef4e087005c6a6e"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-08-14 19:51:13"
  condition:
    hash.sha256(0, filesize) == "f06db00d66ee3be3c536bd1cde95514c852ca08261af889acef4e087005c6a6e"
}

rule MalwareBazaar_Vidar_079_63eedb85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33"
    family = "Vidar"
    file_name = "63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33.exe"
    file_type = "exe"
    first_seen = "2026-08-14 19:49:39"
  condition:
    hash.sha256(0, filesize) == "63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33"
}

rule MalwareBazaar_unknown_080_5ee2f468
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ee2f468fac76514a39aac80f78a48a36a3a6585460017bfccca54e4afeb13c2"
    family = "unknown"
    file_name = "ue"
    file_type = "exe"
    first_seen = "2026-08-14 19:28:40"
  condition:
    hash.sha256(0, filesize) == "5ee2f468fac76514a39aac80f78a48a36a3a6585460017bfccca54e4afeb13c2"
}

rule MalwareBazaar_Mirai_081_9ccef67a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ccef67ad0da073d31a8d5e3b5de18858fe8995c2ea1ebd06be65bbf4f094327"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:43"
  condition:
    hash.sha256(0, filesize) == "9ccef67ad0da073d31a8d5e3b5de18858fe8995c2ea1ebd06be65bbf4f094327"
}

rule MalwareBazaar_Mirai_082_56e5fa7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e5fa7e2166605afbebfdd75225c7ee967c6b90f24b8fb467e3344b3140bf8a"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:41"
  condition:
    hash.sha256(0, filesize) == "56e5fa7e2166605afbebfdd75225c7ee967c6b90f24b8fb467e3344b3140bf8a"
}

rule MalwareBazaar_Mirai_083_06cb82ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06cb82aed522086b5e0d6c138d9f402b2f8df755145072aa1aebf0ea34fc050f"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:40"
  condition:
    hash.sha256(0, filesize) == "06cb82aed522086b5e0d6c138d9f402b2f8df755145072aa1aebf0ea34fc050f"
}

rule MalwareBazaar_Mirai_084_e4ebc4f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4ebc4f617407f97ad0e7208014c559dc7b9418b48ae320aaf6f3f24027fdbbd"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:39"
  condition:
    hash.sha256(0, filesize) == "e4ebc4f617407f97ad0e7208014c559dc7b9418b48ae320aaf6f3f24027fdbbd"
}

rule MalwareBazaar_Mirai_085_253f87d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "253f87d887637ca92d57113b189992ceb81507ea4f4e72cc18f64ed4600a6fb1"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:38"
  condition:
    hash.sha256(0, filesize) == "253f87d887637ca92d57113b189992ceb81507ea4f4e72cc18f64ed4600a6fb1"
}

rule MalwareBazaar_Mirai_086_03ad6e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03ad6e6970a3a4e00d40b03068b50619f4f51360e4d9d845433215c262f97489"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:36"
  condition:
    hash.sha256(0, filesize) == "03ad6e6970a3a4e00d40b03068b50619f4f51360e4d9d845433215c262f97489"
}

rule MalwareBazaar_Mirai_087_980245b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "980245b5b8929338e63ff710d262859b157cf72e0fb7c89e28913cc48b57dff4"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:35"
  condition:
    hash.sha256(0, filesize) == "980245b5b8929338e63ff710d262859b157cf72e0fb7c89e28913cc48b57dff4"
}

rule MalwareBazaar_Mirai_088_e6ef1f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6ef1f96ef026f2347849fc330a2659246a39a07bebc4560eb6a355142b98c5d"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-14 19:17:34"
  condition:
    hash.sha256(0, filesize) == "e6ef1f96ef026f2347849fc330a2659246a39a07bebc4560eb6a355142b98c5d"
}

rule MalwareBazaar_RustyStealer_089_d4aaf92e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4aaf92e411b242f454647d7a6d1b3657a4699e419b273e7e4b63ce4d2cccb3c"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 19:17:28"
  condition:
    hash.sha256(0, filesize) == "d4aaf92e411b242f454647d7a6d1b3657a4699e419b273e7e4b63ce4d2cccb3c"
}

rule MalwareBazaar_Mirai_090_8810fade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8810fadecf4f25d249dcc33abb215c5d3c072ba11a86815efda9f51874cd1e4b"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-14 19:15:18"
  condition:
    hash.sha256(0, filesize) == "8810fadecf4f25d249dcc33abb215c5d3c072ba11a86815efda9f51874cd1e4b"
}

rule MalwareBazaar_Mirai_091_7dc5b780
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc5b78098d56c3efb6ed453be5fc55a117544711973837a7a6529b20b609061"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-14 19:15:16"
  condition:
    hash.sha256(0, filesize) == "7dc5b78098d56c3efb6ed453be5fc55a117544711973837a7a6529b20b609061"
}

rule MalwareBazaar_unknown_092_d5e645ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5e645ff8635073533fed23a1db7a64e8391205c822820352add8e2b58aa4319"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 19:08:43"
  condition:
    hash.sha256(0, filesize) == "d5e645ff8635073533fed23a1db7a64e8391205c822820352add8e2b58aa4319"
}

rule MalwareBazaar_unknown_093_51b72c4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51b72c4f307600f39077630b63cf3748b2db88c66ab0ea2c48c056af14a50c5d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-14 19:08:34"
  condition:
    hash.sha256(0, filesize) == "51b72c4f307600f39077630b63cf3748b2db88c66ab0ea2c48c056af14a50c5d"
}

rule MalwareBazaar_njrat_094_33211c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33211c0e7a7b9545c13addcd452b68ab0f72b2d5fad857a7a3dd75c34a3fff09"
    family = "njrat"
    file_name = "F168APP.exe"
    file_type = "exe"
    first_seen = "2026-08-14 18:53:57"
  condition:
    hash.sha256(0, filesize) == "33211c0e7a7b9545c13addcd452b68ab0f72b2d5fad857a7a3dd75c34a3fff09"
}

rule MalwareBazaar_unknown_095_747f8f2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "747f8f2c557f5ca2ff3ac797ffe4df4b2e042a747e5d728060c49bda2466e5c0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 18:53:29"
  condition:
    hash.sha256(0, filesize) == "747f8f2c557f5ca2ff3ac797ffe4df4b2e042a747e5d728060c49bda2466e5c0"
}

rule MalwareBazaar_unknown_096_d7f44f83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7f44f8336a745e0b074faa039203126b26ce7e46d89301fc9233fe2e193d6cf"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 17:52:32"
  condition:
    hash.sha256(0, filesize) == "d7f44f8336a745e0b074faa039203126b26ce7e46d89301fc9233fe2e193d6cf"
}

rule MalwareBazaar_AsyncRAT_097_00180c06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2"
    family = "AsyncRAT"
    file_name = "00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2"
    file_type = "exe"
    first_seen = "2026-08-14 17:40:05"
  condition:
    hash.sha256(0, filesize) == "00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2"
}

rule MalwareBazaar_unknown_098_439d40c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3"
    family = "unknown"
    file_name = "439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3"
    file_type = "dll"
    first_seen = "2026-08-14 17:38:03"
  condition:
    hash.sha256(0, filesize) == "439d40c57e8d7bb72378735560cf7c1a863909860f12a92b50be712716936ad3"
}

rule MalwareBazaar_AsyncRAT_099_06a98cd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85"
    family = "AsyncRAT"
    file_name = "06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85.js"
    file_type = "js"
    first_seen = "2026-08-14 17:36:43"
  condition:
    hash.sha256(0, filesize) == "06a98cd523b8d3bd164562694c41832d88825ee043a29e19fc05e19954a79a85"
}

rule MalwareBazaar_RemoteX_100_190c466c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "190c466cd581085a3037192247db1b0cbfc67fb92fe3cead3e5f0c4683f8f4ef"
    family = "RemoteX"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-14 17:18:24"
  condition:
    hash.sha256(0, filesize) == "190c466cd581085a3037192247db1b0cbfc67fb92fe3cead3e5f0c4683f8f4ef"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

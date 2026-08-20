# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-20

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 598 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 598 |
| Unique family labels | 10 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 50 |
| Mirai | 39 |
| DCRat | 2 |
| RemusStealer | 2 |
| ConnectWise | 2 |
| ValleyRAT | 1 |
| WannaCry | 1 |
| njrat | 1 |
| MeshAgent | 1 |
| RemcosRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 43 |
| exe | 20 |
| unknown | 12 |
| sh | 7 |
| zip | 5 |
| bat | 3 |
| vbe | 3 |
| vbs | 2 |
| msi | 2 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `9df49e9a905999b0`

| Field | Value |
|---|---|
| SHA-256 | `9df49e9a905999b066c1994261c2aefa40bbfe54ff978ea75c131dc7e1a573b9` |
| Family label | `ValleyRAT` |
| File name | `8E2FF0A0925C9D4FDBCC3DCACAF7C9B6.dll` |
| File type | `dll` |
| First seen | `2026-08-20 01:50:15` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e2ff0a0925c9d4fdbcc3dcacaf7c9b6` |
| SHA-1 | `0e6baf320f27561637d12f09cb78728982ba200c` |
| SHA-256 | `9df49e9a905999b066c1994261c2aefa40bbfe54ff978ea75c131dc7e1a573b9` |
| SHA3-384 | `0cb9cf9386151abc4c1374c2612579801165dbe64e4cd134245d4bfd620c882a1fc789cca368e1c7798d220c2386130c` |
| IMPHASH | `40cf81d7b90d369a5cd511a276c353b5` |
| TLSH | `T19F56D0117DEC0467E0AB03318EAAF2BC35BEBDA43F2561672784F61EF9313515A1522B` |
| SSDEEP | `98304:Jjv0DwP38wtCkCUyFJeT5ihmAcmI5JWROVYoZ4OiZrq1DfPHNADtV6v+zM+rwroX:Jjb38w9bkmAcmI+MV9Z4O7NADtV6v+zn` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_001_9df49e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9df49e9a905999b066c1994261c2aefa40bbfe54ff978ea75c131dc7e1a573b9"
    family = "ValleyRAT"
    file_name = "8E2FF0A0925C9D4FDBCC3DCACAF7C9B6.dll"
    file_type = "dll"
    first_seen = "2026-08-20 01:50:15"
  condition:
    hash.sha256(0, filesize) == "9df49e9a905999b066c1994261c2aefa40bbfe54ff978ea75c131dc7e1a573b9"
}
```

### Sample 2: `c634f2071b0725a0`

| Field | Value |
|---|---|
| SHA-256 | `c634f2071b0725a0d2c29852fb0b7bae3489ea724c1c3a0943ed71582a054c50` |
| Family label | `unknown` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-08-20 01:31:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46db42c7cffcbfa27a12d8c091a3f90b` |
| SHA-1 | `f31ad5dcc6a18d9b87edb60249ab09f80d736891` |
| SHA-256 | `c634f2071b0725a0d2c29852fb0b7bae3489ea724c1c3a0943ed71582a054c50` |
| SHA3-384 | `ea01f89b4295fd56d4bea970b90af1e8024203396417ed790a4fb54e5a8275659aa38c42d5e6063c50ced21b9a781262` |
| TLSH | `T1FAC45C17A6E370FCC1E7D03487AB9663AA71B43552257EBF55C8DE702E16E20230DB62` |
| SSDEEP | `12288:gO3b6OVhjMD07BPLzgNM3EtuBSY4s0aD/ok8R7lgmr9vkTv54Qnv:g/YhjwaBLzgC0oj4sak8R7ioMTR4Qnv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_c634f207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c634f2071b0725a0d2c29852fb0b7bae3489ea724c1c3a0943ed71582a054c50"
    family = "unknown"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 01:31:40"
  condition:
    hash.sha256(0, filesize) == "c634f2071b0725a0d2c29852fb0b7bae3489ea724c1c3a0943ed71582a054c50"
}
```

### Sample 3: `c897c15850310c24`

| Field | Value |
|---|---|
| SHA-256 | `c897c15850310c244a6d8f27a6c0387d6359b1326120c8eca9ee27d4c6a6ff3c` |
| Family label | `Mirai` |
| File name | `data_arm5` |
| File type | `elf` |
| First seen | `2026-08-20 00:58:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5bda1237720b21616e5cf44fa18b40a` |
| SHA-1 | `256902fa13f6f920a34196430642f577502480a9` |
| SHA-256 | `c897c15850310c244a6d8f27a6c0387d6359b1326120c8eca9ee27d4c6a6ff3c` |
| SHA3-384 | `09f174b5f7e9bdce8bf35465c2d0e65e4f76a280a0a9d100cdea0c30a514fde9f4a93c12c3a57ebcd391a0c10c4e9ae9` |
| TLSH | `T118343D52BD41DF53C6C12ABBFBAE824837132B7DD6EE3102E9146F21279B8960E77501` |
| TELFHASH | `t1574144a6cb3229ec53d0412872de71395ead31ec2b2328d199e5ab0f0c53ec1705db3a` |
| SSDEEP | `6144:nq8XlCVDOxnzSXYjNgzZGLfFGlB2xY4iuhMB5BZEDTcsy:qKlCqlxQGLfFGlBQzhsDZEDTc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_c897c158
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c897c15850310c244a6d8f27a6c0387d6359b1326120c8eca9ee27d4c6a6ff3c"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-20 00:58:48"
  condition:
    hash.sha256(0, filesize) == "c897c15850310c244a6d8f27a6c0387d6359b1326120c8eca9ee27d4c6a6ff3c"
}
```

### Sample 4: `8bc94ede491e67b3`

| Field | Value |
|---|---|
| SHA-256 | `8bc94ede491e67b32af3789f9807b76bebe02f69bb9dbec17342c1e00bd6d7d3` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-08-20 00:58:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d7848510bf397b229b7a928346cb3ef` |
| SHA-1 | `9c4d9be186ffeb818380d49245652143cf53c691` |
| SHA-256 | `8bc94ede491e67b32af3789f9807b76bebe02f69bb9dbec17342c1e00bd6d7d3` |
| SHA3-384 | `29776ecd0ede0449fee9c623c5193f317bbc7204d650db2961581875512e680505920ca6bd4b01ed055f982af97b4fe5` |
| TLSH | `T155443B66E9419B91D5C12AFEFF6E814933172F7CE3EE7102DD145F2067CA88A0E7A501` |
| TELFHASH | `t13f412e2597252abca3d2589841ae38060a7c35dc3b1234d3969ddf4b4d13ed1f1fa83a` |
| SSDEEP | `6144:DqFgJ7+xwX6V9ZCx1g7C1p3TK9RhCZYp7aFFdLeMo16ZSfvYp47aS:m+x+V9Sgm3TK9RhCSp7afdLeMo164HYs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_8bc94ede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bc94ede491e67b32af3789f9807b76bebe02f69bb9dbec17342c1e00bd6d7d3"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-20 00:58:47"
  condition:
    hash.sha256(0, filesize) == "8bc94ede491e67b32af3789f9807b76bebe02f69bb9dbec17342c1e00bd6d7d3"
}
```

### Sample 5: `fd84e3dcb36b5480`

| Field | Value |
|---|---|
| SHA-256 | `fd84e3dcb36b548098af61a9d3479ca0b8e2ab5e9e688bda32a0fb34d0e93806` |
| Family label | `unknown` |
| File name | `data_aarch64` |
| File type | `elf` |
| First seen | `2026-08-20 00:58:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f67e921de8ab05228f32bf8d446f44bb` |
| SHA-1 | `76f0152237fd2bab2699a5f732a83fae7bd062b6` |
| SHA-256 | `fd84e3dcb36b548098af61a9d3479ca0b8e2ab5e9e688bda32a0fb34d0e93806` |
| SHA3-384 | `dab83cdbb937f04f3a356306c34cf97902fbb874fc4145159cbff72173ec1e5b35c196d697017503184442239845afff` |
| TLSH | `T176C47C98EE4E7D4293C7F27CAE994BE1302B35E8D32780F62A92065DD5D9ED8C5F1120` |
| SSDEEP | `12288:QhMBrG/SbYhW1pOKknGMMGnlbmlX3+2jLrDBxFTJjHJ46y1:QhyS/jhWWKknGE8bjLrDxvw1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_fd84e3dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd84e3dcb36b548098af61a9d3479ca0b8e2ab5e9e688bda32a0fb34d0e93806"
    family = "unknown"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-08-20 00:58:46"
  condition:
    hash.sha256(0, filesize) == "fd84e3dcb36b548098af61a9d3479ca0b8e2ab5e9e688bda32a0fb34d0e93806"
}
```

### Sample 6: `8182fb0126fe3f44`

| Field | Value |
|---|---|
| SHA-256 | `8182fb0126fe3f44eaf12f065a054a64ecfb73b884f68969ebbdc15cfeffba29` |
| Family label | `Mirai` |
| File name | `data_powerpc` |
| File type | `elf` |
| First seen | `2026-08-20 00:55:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43d865aee32f1a6760eae078e2b9ff9f` |
| SHA-1 | `c8c219ac496757984650af649f8d52fada28fee9` |
| SHA-256 | `8182fb0126fe3f44eaf12f065a054a64ecfb73b884f68969ebbdc15cfeffba29` |
| SHA3-384 | `1089bb23afd9715b5bf53823c1422770ab123327c8f44e37f753106d8211422ab7a6398e8806aba988585b7f317768b1` |
| TLSH | `T189443B02771D0F43E2A32DF0373B17E197AEADA124E9E584690EBEC65371D721189ACD` |
| SSDEEP | `6144:7fNcCfSWzC/wL7PzU6u6GaolUg3Ib8RQzwTO6e9dZff/B2sF:7fNcC6gvjg7Gf/B2sF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_8182fb01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8182fb0126fe3f44eaf12f065a054a64ecfb73b884f68969ebbdc15cfeffba29"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:56"
  condition:
    hash.sha256(0, filesize) == "8182fb0126fe3f44eaf12f065a054a64ecfb73b884f68969ebbdc15cfeffba29"
}
```

### Sample 7: `57ba0c6c3195857e`

| Field | Value |
|---|---|
| SHA-256 | `57ba0c6c3195857e972d9764566e57db25a5e49de4efb8f7ffb545f74740b123` |
| Family label | `Mirai` |
| File name | `data_arm6` |
| File type | `elf` |
| First seen | `2026-08-20 00:55:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d0f3bbf605a0b5f03ba8c41f9c0e70b` |
| SHA-1 | `fbf7c897e2fabfeb3a74a5b33227921d5ba978a1` |
| SHA-256 | `57ba0c6c3195857e972d9764566e57db25a5e49de4efb8f7ffb545f74740b123` |
| SHA3-384 | `8eeadf23e7b602e26cb4ff2a88012e3ccefcb3c7daf645edc70696065ad7919310bea097f10aa041a2364e20b9dbe765` |
| TLSH | `T14C443C66E841DB92D1C11ABEFF6DC14933172F78E3EE7202DD146F60678B89A0E7A501` |
| TELFHASH | `t1b8019c62426712fc67d01404c9de2322d9ac21581b115cea9bddadc75973ae4f8f191c` |
| SSDEEP | `6144:NIcvL+V1sshDIR/aR+N4I0STXAMt5ZJ04a1gou5y29I1NWN:OaL0hDYNISTXAMt5w4aaJ5y29I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_57ba0c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57ba0c6c3195857e972d9764566e57db25a5e49de4efb8f7ffb545f74740b123"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:55"
  condition:
    hash.sha256(0, filesize) == "57ba0c6c3195857e972d9764566e57db25a5e49de4efb8f7ffb545f74740b123"
}
```

### Sample 8: `87d14d2c5609cefb`

| Field | Value |
|---|---|
| SHA-256 | `87d14d2c5609cefb229cd3fff7a708e7bc357a92ae4348382e2bbdd3d3b7ae4c` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-08-20 00:55:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e33a0aa3b871ded56b78bf7ab050ec98` |
| SHA-1 | `302034ffbee947fa524703eed546ae50492b4293` |
| SHA-256 | `87d14d2c5609cefb229cd3fff7a708e7bc357a92ae4348382e2bbdd3d3b7ae4c` |
| SHA3-384 | `6321b0d7f15b9ffc73aa500202105e06df386a339728142f519435223479f9393e75a894295019e5816733beb430d5f0` |
| TLSH | `T17A343C62BD41DF93C6C12AFBFBAE824837172B7DD5EE3102DD146F61239A8960E36501` |
| TELFHASH | `t1e84154952b301fdca7d4802551ee651a8d5d32dc3f3124d149daea8f0493a93b4eac3a` |
| SSDEEP | `6144:7M+iSbcCFXBU6voZYi7Pn8L0FLelAuneQF+aZvM6o2N88Dx0y:7riSQIe7P8selAuneQU4vMj28yx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_87d14d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87d14d2c5609cefb229cd3fff7a708e7bc357a92ae4348382e2bbdd3d3b7ae4c"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:54"
  condition:
    hash.sha256(0, filesize) == "87d14d2c5609cefb229cd3fff7a708e7bc357a92ae4348382e2bbdd3d3b7ae4c"
}
```

### Sample 9: `e266c8d3b55220ad`

| Field | Value |
|---|---|
| SHA-256 | `e266c8d3b55220ad94d6c27da4758809bf0e8c359aeb63e6592a6de52a216c95` |
| Family label | `unknown` |
| File name | `bbc` |
| File type | `sh` |
| First seen | `2026-08-20 00:55:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac51c9405fb30f330ee015600ff52391` |
| SHA-1 | `75a1fd3445b5a4ac9188dbcc6893b1c71dd288f7` |
| SHA-256 | `e266c8d3b55220ad94d6c27da4758809bf0e8c359aeb63e6592a6de52a216c95` |
| SHA3-384 | `a5fa32e1457a8c2adfcbef66f14998c056781c2e912b43f8492740db1eb2b7380bda67be135264abe9ba6b40e10672a2` |
| TLSH | `T19CF0A703B48BF032804039E4DB66F75AFC347D476262DE4CB8407A60DFD34347861244` |
| SSDEEP | `12:lSjhh1OL9ephRjk4Y4bou7Co1VOq2xddNizdI/HXoBeXx:lk1gYpTr8i3fOq2bf8Iyeh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_e266c8d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e266c8d3b55220ad94d6c27da4758809bf0e8c359aeb63e6592a6de52a216c95"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-08-20 00:55:52"
  condition:
    hash.sha256(0, filesize) == "e266c8d3b55220ad94d6c27da4758809bf0e8c359aeb63e6592a6de52a216c95"
}
```

### Sample 10: `a2a18c18182243ce`

| Field | Value |
|---|---|
| SHA-256 | `a2a18c18182243ce6b54481ae362535871b4111a9204b39aab6fb8a46d93255d` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-08-20 00:55:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8afa498b51ac428a6026f9a7aa7fd30` |
| SHA-1 | `f416f5b3f62463b8894ca931172885c552383d40` |
| SHA-256 | `a2a18c18182243ce6b54481ae362535871b4111a9204b39aab6fb8a46d93255d` |
| SHA3-384 | `20c68b868ad015831dd0d7671dc28e157dba7c04960b11b21a2e5b48dfceabacb1184ac6982d7232eec726d90d34b857` |
| TLSH | `T125559F07B7B374BEC053C435879BD662AA32B42502126E7F61C4DA343E17EA45F1EB62` |
| TELFHASH | `t1e142520e5b2287577d6184c867a9abd32907850b8b9d8be08de48b0fc6700b7fd168dd` |
| SSDEEP | `24576:g/YhjwaBLzgC0oj4sak8R7ioMTR4Qn7040/Pf7tsURQXn/ZGNZncGmpY:YYhjXgCpj4sake6sTLtsURmZGNSY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_a2a18c18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2a18c18182243ce6b54481ae362535871b4111a9204b39aab6fb8a46d93255d"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:51"
  condition:
    hash.sha256(0, filesize) == "a2a18c18182243ce6b54481ae362535871b4111a9204b39aab6fb8a46d93255d"
}
```

### Sample 11: `f8439179f9c964fb`

| Field | Value |
|---|---|
| SHA-256 | `f8439179f9c964fbefb1ffef0a6749a772242fee4b9432976bf6b587b786a2c8` |
| Family label | `Mirai` |
| File name | `data_x86` |
| File type | `elf` |
| First seen | `2026-08-20 00:55:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77ceb458ea7e232481101b6e0f21bed4` |
| SHA-1 | `490fcc4bc0bbbb267ca5bb7939add443cc26a941` |
| SHA-256 | `f8439179f9c964fbefb1ffef0a6749a772242fee4b9432976bf6b587b786a2c8` |
| SHA3-384 | `618dba31241515a7543541d759b8cc9195a5e272d56f1ac90b16fdaa6492dd61aa53d7c5cf241248e4639582bd8db1f7` |
| TLSH | `T1C7357C9CE3C7D4F1F26341F1021ED7B75534A1299023FAF6EF4A2A6674327522F1A21A` |
| TELFHASH | `t152229db33c6969ec7bf08826829b3620ce66e13b55a0357204f361d1fab7e035a75c75` |
| SSDEEP | `24576:mV7H2HJ/STXhknh69PMFBn2q9ggdTlmw5x6:pEhknh69iBnt3D5U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_f8439179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8439179f9c964fbefb1ffef0a6749a772242fee4b9432976bf6b587b786a2c8"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:49"
  condition:
    hash.sha256(0, filesize) == "f8439179f9c964fbefb1ffef0a6749a772242fee4b9432976bf6b587b786a2c8"
}
```

### Sample 12: `3f205f6073c62cd2`

| Field | Value |
|---|---|
| SHA-256 | `3f205f6073c62cd2e6f5499f07c0fb3ed269d3494a2bb8668d80fb3d95b28fc2` |
| Family label | `Mirai` |
| File name | `data_mips` |
| File type | `elf` |
| First seen | `2026-08-20 00:55:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10dea37f55e9d29b6ce7979835311b73` |
| SHA-1 | `2282283a3f0d7652d16ad0322d7483303013fd3b` |
| SHA-256 | `3f205f6073c62cd2e6f5499f07c0fb3ed269d3494a2bb8668d80fb3d95b28fc2` |
| SHA3-384 | `51315606b7878527763c5e135f20f48e23cd7858960eda5537fba6d4a7f4e4da9937dd820f410719863246567685d012` |
| TLSH | `T1E374B40A6E228F7DF27587708BF34E20D76D73D616E1D684E2ACD5050F2068E651FBA8` |
| TELFHASH | `t113816dea297507b4a648984d45dcfe158da728ef3e4a0c33da61d49ed71bbc35e10c1c` |
| SSDEEP | `6144:znpXAQQbytzcFiJrxKnHjwmVQ3Kf15jA7Mkw3YDPC6vsyylCC0V/QOLjHqVkH5DR:z0YQLydQqHqY5Dmq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_3f205f60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f205f6073c62cd2e6f5499f07c0fb3ed269d3494a2bb8668d80fb3d95b28fc2"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:48"
  condition:
    hash.sha256(0, filesize) == "3f205f6073c62cd2e6f5499f07c0fb3ed269d3494a2bb8668d80fb3d95b28fc2"
}
```

### Sample 13: `fe8815cedb65e08a`

| Field | Value |
|---|---|
| SHA-256 | `fe8815cedb65e08a83ce35a86a3b26d7297134029b60f64dc210e51ad5d7845a` |
| Family label | `unknown` |
| File name | `data_mipsel` |
| File type | `elf` |
| First seen | `2026-08-20 00:55:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `150e2faa6f6aed0c9e81f175a8fc4cfb` |
| SHA-1 | `32ca1f762adcc88437606c0d095dc3bdd54da1c8` |
| SHA-256 | `fe8815cedb65e08a83ce35a86a3b26d7297134029b60f64dc210e51ad5d7845a` |
| SHA3-384 | `fc9eed2a79078f9f31a357a91c75e5597cdfc88dfb959d5480d2e3a284e0842fee113c03294c454f68da8c590713f000` |
| TLSH | `T1FF34C7096F640EFBE86BCD3B06A91B1635CDB84371993F367478DD04B94A60B4AD3878` |
| SSDEEP | `3072:imIUc6H3LV4UmsvN6HYGjX8nOAVUW1o4uCG1/9IdvpGy8LSQH:HHyUmsvN64q8nOYUhvP418LSq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_fe8815ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe8815cedb65e08a83ce35a86a3b26d7297134029b60f64dc210e51ad5d7845a"
    family = "unknown"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:47"
  condition:
    hash.sha256(0, filesize) == "fe8815cedb65e08a83ce35a86a3b26d7297134029b60f64dc210e51ad5d7845a"
}
```

### Sample 14: `5be539b6e019787a`

| Field | Value |
|---|---|
| SHA-256 | `5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1` |
| Family label | `unknown` |
| File name | `5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1.bin` |
| File type | `exe` |
| First seen | `2026-08-20 00:11:35` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b5e1694a6a60eaa2ac4aa05e49cc1d2` |
| SHA-1 | `af01b1db628b65736629259a5cb0f98929dc4007` |
| SHA-256 | `5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1` |
| SHA3-384 | `c558ef6a703fafbe1ee1f12ed9bb4339c752d76d268a1fed5f9b0c5a1d33575d40654d693c1a2145f38f31cdbefd32ee` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1CB366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaX:uc3XND1aJrCOkX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_5be539b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1"
    family = "unknown"
    file_name = "5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1.bin"
    file_type = "exe"
    first_seen = "2026-08-20 00:11:35"
  condition:
    hash.sha256(0, filesize) == "5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1"
}
```

### Sample 15: `1b7d970654a2a88e`

| Field | Value |
|---|---|
| SHA-256 | `1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872` |
| Family label | `unknown` |
| File name | `1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872.bin` |
| File type | `unknown` |
| First seen | `2026-08-19 23:55:48` |
| Reporter | `Tuxxin` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d7d2ba437b72101e5afd90045f9e6ac` |
| SHA-256 | `1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_1b7d9706
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872"
    family = "unknown"
    file_name = "1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 23:55:48"
  condition:
    hash.sha256(0, filesize) == "1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872"
}
```

### Sample 16: `809c23d1a24c9ee5`

| Field | Value |
|---|---|
| SHA-256 | `809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f` |
| Family label | `WannaCry` |
| File name | `809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f` |
| File type | `exe` |
| First seen | `2026-08-19 23:48:09` |
| Reporter | `TawnyBalfour` |
| Tags | `dionaea, exe, honeypot, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7369456ebc98f01f4af999658dd4139` |
| SHA-1 | `9f7089b730d94746fddf45e33d05a5888f5041e7` |
| SHA-256 | `809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f` |
| SHA3-384 | `1312a6cd0db015d331f395808110a406643be860e47046de2b67d15492019de95a28f1887e2fcad655ff823924727821` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T15BF5C00A379CC0B8C4569274D8B74E25E7B7BC4A1338864F1B64CB6A1F63391B979B13` |
| SSDEEP | `6144:jIYVTH5DgSgmE9l9yNqIYVTH5DgSg8ajldktM0XXrs2:jbLgmwbLgPlux` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_016_809c23d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f"
    family = "WannaCry"
    file_name = "809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f"
    file_type = "exe"
    first_seen = "2026-08-19 23:48:09"
  condition:
    hash.sha256(0, filesize) == "809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f"
}
```

### Sample 17: `1f12614ae3595a8c`

| Field | Value |
|---|---|
| SHA-256 | `1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e` |
| Family label | `unknown` |
| File name | `1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e.bin` |
| File type | `zip` |
| First seen | `2026-08-19 23:45:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23c5039c1f6b167861616ec276596001` |
| SHA-1 | `dc3126c0aefe0fe708e53317d8baf16a8db6096d` |
| SHA-256 | `1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e` |
| SHA3-384 | `0fba6f375e2a9064adaa819810a31cea8bc8f295ce05f8b97f9af7dde92760aeaebaf20a2d11cb2d7c88d86efe23b341` |
| TLSH | `T1194533CDC8A93B435CF364E91CDB2E5C1A0CB4FAD35BD78E5090A426290947F9E4BC66` |
| SSDEEP | `24576:nRY5PzbIrsObRfIzyeEwK9bxUEXrI0dBZk5KZPAaW5qBQoBrEoMMyYBa4eixt9t1:64VfteEwA7rIsmKdc5xXi+4J97` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_1f12614a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e"
    family = "unknown"
    file_name = "1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e.bin"
    file_type = "zip"
    first_seen = "2026-08-19 23:45:52"
  condition:
    hash.sha256(0, filesize) == "1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e"
}
```

### Sample 18: `b3f2ff2437ceb642`

| Field | Value |
|---|---|
| SHA-256 | `b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e` |
| Family label | `unknown` |
| File name | `b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e.elf` |
| File type | `elf` |
| First seen | `2026-08-19 23:40:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd2313d7acc97788c54ab26e4b5f1de8` |
| SHA-1 | `4ed92cbfde885febea27348abc967f5e57ef74e2` |
| SHA-256 | `b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e` |
| SHA3-384 | `758fc169b99ba487fc3d35ae80209e22166f2578571531b81a92ca53eb85acfd9527089bf78e55db47d683efd9e798ad` |
| TLSH | `T176C31862BC42D846C4D866BAEB5EC3C93347A3B8D2DD3412EC02C63459CE5D94F3AB65` |
| TELFHASH | `t1e3117dd064aae454b2d7dca0a6fff90a5632629eef5926178640f93c9c877c41401d27` |
| SSDEEP | `1536:XmdA23WYicbLQtG+QIndnszm59MLtlzHyJ0SCbTMEOqe6f4Hvc7csju3hVDNRkjX:XmqGiOLQtGTI2zm5mjfg1rJy949gFvnb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_b3f2ff24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e"
    family = "unknown"
    file_name = "b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e.elf"
    file_type = "elf"
    first_seen = "2026-08-19 23:40:50"
  condition:
    hash.sha256(0, filesize) == "b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e"
}
```

### Sample 19: `5d8bfb8c4b67e289`

| Field | Value |
|---|---|
| SHA-256 | `5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a` |
| Family label | `unknown` |
| File name | `5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a.bin` |
| File type | `unknown` |
| First seen | `2026-08-19 23:27:00` |
| Reporter | `Tuxxin` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e713453fe814cfee3f806d0d92e953c` |
| SHA-256 | `5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_5d8bfb8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a"
    family = "unknown"
    file_name = "5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 23:27:00"
  condition:
    hash.sha256(0, filesize) == "5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a"
}
```

### Sample 20: `7da8c7aa6b48cb72`

| Field | Value |
|---|---|
| SHA-256 | `7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c` |
| Family label | `unknown` |
| File name | `7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c.bin` |
| File type | `unknown` |
| First seen | `2026-08-19 23:23:48` |
| Reporter | `Tuxxin` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e458b674e28a12cc2365e0027a955939` |
| SHA-256 | `7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_7da8c7aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c"
    family = "unknown"
    file_name = "7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 23:23:48"
  condition:
    hash.sha256(0, filesize) == "7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c"
}
```

### Sample 21: `7628144c2c2cb841`

| Field | Value |
|---|---|
| SHA-256 | `7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061` |
| Family label | `unknown` |
| File name | `7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061.bin` |
| File type | `unknown` |
| First seen | `2026-08-19 22:50:54` |
| Reporter | `Tuxxin` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b4eff073d3f1bdc133c7c709da0bc96` |
| SHA-256 | `7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_7628144c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061"
    family = "unknown"
    file_name = "7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 22:50:54"
  condition:
    hash.sha256(0, filesize) == "7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061"
}
```

### Sample 22: `d86bf7e59e632092`

| Field | Value |
|---|---|
| SHA-256 | `d86bf7e59e6320920f737526089e4dfac56bacf346ae60d6d6bce015b33953cb` |
| Family label | `DCRat` |
| File name | `254559fa505cfe6b680dc477cfe11dba.exe` |
| File type | `exe` |
| First seen | `2026-08-19 22:50:10` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `254559fa505cfe6b680dc477cfe11dba` |
| SHA-1 | `bfc24227d23288b828b7af4d357875a038ae12c3` |
| SHA-256 | `d86bf7e59e6320920f737526089e4dfac56bacf346ae60d6d6bce015b33953cb` |
| SHA3-384 | `5f58f4783a2767cd86fa3500065a22de7d7c6c62bd30127279b3d31401acaeab400495e0866646f6d576e6813a93227f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1EF455B027E54CE12F0192233D2EF454847B499516AA7E32B7DBA37AD25123A73D0DACF` |
| SSDEEP | `24576:almh9QxzhxVYrMcr7oiDkPeJaRr9aGyPSLXDy7oSS9jLN:o49+V+iK9EXWsx9` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_022_d86bf7e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86bf7e59e6320920f737526089e4dfac56bacf346ae60d6d6bce015b33953cb"
    family = "DCRat"
    file_name = "254559fa505cfe6b680dc477cfe11dba.exe"
    file_type = "exe"
    first_seen = "2026-08-19 22:50:10"
  condition:
    hash.sha256(0, filesize) == "d86bf7e59e6320920f737526089e4dfac56bacf346ae60d6d6bce015b33953cb"
}
```

### Sample 23: `d3692f7f99d26b8e`

| Field | Value |
|---|---|
| SHA-256 | `d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485` |
| Family label | `unknown` |
| File name | `d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485.bin` |
| File type | `exe` |
| First seen | `2026-08-19 22:06:43` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `643f724637e75f662ee5a52be00775b9` |
| SHA-1 | `23831457d0f8578c59573a93bfe52fd7c9207b83` |
| SHA-256 | `d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485` |
| SHA3-384 | `eaae34be17c35f3771aee68ce2e3c752e024994f3bb5e9cfb3f6a97fe1ecbbbcd4dcdc0c3e459f8509684f3311bac4d7` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T189668C17FC6510A5C5EAE334C9765252B630B8894B3473E72F61BAB42F7A7C06EB8740` |
| SSDEEP | `49152:YOWi6TPEzFtbpDurb/TsvO90d7HjmAFd4A64nsfJ7VP54rYhkIDNwnlLE7UoGlYC:EEzFpEsUUoIFp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_d3692f7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485"
    family = "unknown"
    file_name = "d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485.bin"
    file_type = "exe"
    first_seen = "2026-08-19 22:06:43"
  condition:
    hash.sha256(0, filesize) == "d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485"
}
```

### Sample 24: `7743d51b055f2743`

| Field | Value |
|---|---|
| SHA-256 | `7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398` |
| Family label | `unknown` |
| File name | `7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398` |
| File type | `unknown` |
| First seen | `2026-08-19 21:54:18` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbf8d867ca22e6ecb1ce9070e09a5493` |
| SHA-256 | `7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_7743d51b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398"
    family = "unknown"
    file_name = "7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398"
    file_type = "unknown"
    first_seen = "2026-08-19 21:54:18"
  condition:
    hash.sha256(0, filesize) == "7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398"
}
```

### Sample 25: `32e9d75275d0daed`

| Field | Value |
|---|---|
| SHA-256 | `32e9d75275d0daed938898678da75b29cca0c9601490ddccb27868837fbae967` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-19 21:35:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26d1dfedae23c086ceca3680d001cd3e` |
| SHA-1 | `83bc904e344f16cada02ba775b637a40462f8cf4` |
| SHA-256 | `32e9d75275d0daed938898678da75b29cca0c9601490ddccb27868837fbae967` |
| SHA3-384 | `b47f3c8d2251f08eb8571d9234b2d8da9d99f5c865ee910d7bd74ff784d508edadf7cc6053385845a10c7713e70be1d8` |
| TLSH | `T187236C6516857C14AE98C4375C7F2F0CB9AD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:nh99NyXsZztC89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:nfHusZ0cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_32e9d752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32e9d75275d0daed938898678da75b29cca0c9601490ddccb27868837fbae967"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-19 21:35:52"
  condition:
    hash.sha256(0, filesize) == "32e9d75275d0daed938898678da75b29cca0c9601490ddccb27868837fbae967"
}
```

### Sample 26: `f58f8c260181fd11`

| Field | Value |
|---|---|
| SHA-256 | `f58f8c260181fd11f4326c978cc648e7b5085eed6ee513a6f4ddef1f4ef5b6bf` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-19 21:34:49` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9d112716e84e01e1f050ccfd55d387c` |
| SHA-1 | `13a23fa48272c94c9abd23bee367c0faa9b78649` |
| SHA-256 | `f58f8c260181fd11f4326c978cc648e7b5085eed6ee513a6f4ddef1f4ef5b6bf` |
| SHA3-384 | `ff3e6648132239db767194bd531d99457944add4b4d012ad3cf45c9f2ad16b1b40a725b1bbb1285b6fba2cdc5d16ddaa` |
| IMPHASH | `dee5868a54a6f3f29e4dfbc6bebe3d20` |
| TLSH | `T1A9B49E94F6A403F9E176C278CD938503F7B1B8491374AADF03E489761F236A25A3E751` |
| SSDEEP | `6144:IE/RJ3mSiKHnbY+PsrT7aItb8w+Dgyikc2kfzejuSMae5kq8N+ouEQRD50j:JiKbYMsrThl8R0/lgWMMouEE2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_f58f8c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f58f8c260181fd11f4326c978cc648e7b5085eed6ee513a6f4ddef1f4ef5b6bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 21:34:49"
  condition:
    hash.sha256(0, filesize) == "f58f8c260181fd11f4326c978cc648e7b5085eed6ee513a6f4ddef1f4ef5b6bf"
}
```

### Sample 27: `4c5972e2d15fb818`

| Field | Value |
|---|---|
| SHA-256 | `4c5972e2d15fb818e463644331724242526d5049ba19c37223e78b23613771a0` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-08-19 21:32:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8232b6d4c8dab8ba972912133f75a411` |
| SHA-1 | `ed2d931ea0133e20b325771eaf5c01334650a4e0` |
| SHA-256 | `4c5972e2d15fb818e463644331724242526d5049ba19c37223e78b23613771a0` |
| SHA3-384 | `ff2089ee4e8a59fa17e45cb78c05a0096a2e000bfb9a49bf798ef863e666defaaff060c69c1841e758b027cb89638043` |
| TLSH | `T19DD097A310B300B020774850F0C7E900B064A73EBC8FC528BF8738301F45346F4952B0` |
| SSDEEP | `6:hT4GckDFoo0DytOqmJxRObAulNXYq9DG+NjVsNXYrkJ:V7VZ+DgozRObPiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_4c5972e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c5972e2d15fb818e463644331724242526d5049ba19c37223e78b23613771a0"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-08-19 21:32:49"
  condition:
    hash.sha256(0, filesize) == "4c5972e2d15fb818e463644331724242526d5049ba19c37223e78b23613771a0"
}
```

### Sample 28: `d60a5dd9baf1be9a`

| Field | Value |
|---|---|
| SHA-256 | `d60a5dd9baf1be9ae780136c614bd4c51a26590fa327156d80763798a85f1741` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-19 21:09:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79d4b8bc401f62f8da07025a5567bea9` |
| SHA-1 | `8acabff75b0a2b9bc60f2943d674d0e84d36c2ea` |
| SHA-256 | `d60a5dd9baf1be9ae780136c614bd4c51a26590fa327156d80763798a85f1741` |
| SHA3-384 | `e0804255d633dc1ceb1cd1846b2b4b7531189b81e8e8bbf02ada1bb1ad2348860219fc856367c46e97bad0e050a9d0a4` |
| TLSH | `T11B3170CA14105A315107CA5E73B23548758EA6FB2C6FDBD8D8080EFD924D79CF162B4E` |
| SSDEEP | `24:3QwxEiMqOFfY30iV+PPiMYMSdRp03E7nw2EiRc+lgrx3:wfY3tVMiMYMWRp03gqrJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_d60a5dd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d60a5dd9baf1be9ae780136c614bd4c51a26590fa327156d80763798a85f1741"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-19 21:09:03"
  condition:
    hash.sha256(0, filesize) == "d60a5dd9baf1be9ae780136c614bd4c51a26590fa327156d80763798a85f1741"
}
```

### Sample 29: `0ff85f5f951339f6`

| Field | Value |
|---|---|
| SHA-256 | `0ff85f5f951339f6c7e77bfca8b4075722b76c1996ffbbf6c1819f813055e406` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-19 20:56:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a3f0fd0f3a2899ec3ce72892b575ac7` |
| SHA-1 | `908a34a0c949eea4f0a6b4d9fe71dec5bd948139` |
| SHA-256 | `0ff85f5f951339f6c7e77bfca8b4075722b76c1996ffbbf6c1819f813055e406` |
| SHA3-384 | `20020a22f1f006e10f970ee9bb4d9364e1800dc86493b43c95dcf2e5284601c27fb3ca8cee2af138d97bc8cf44acffca` |
| TLSH | `T153143AC3F900DABAF84AF73744530816B130FBA214925A376257357FED7A195183BE8A` |
| SSDEEP | `6144:KG3NdGjQw4gy/vJrTutGgJKhUMLdIwa4nYERqEeWST:jDuJofST` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_0ff85f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ff85f5f951339f6c7e77bfca8b4075722b76c1996ffbbf6c1819f813055e406"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-19 20:56:54"
  condition:
    hash.sha256(0, filesize) == "0ff85f5f951339f6c7e77bfca8b4075722b76c1996ffbbf6c1819f813055e406"
}
```

### Sample 30: `9bf57603ac37a59e`

| Field | Value |
|---|---|
| SHA-256 | `9bf57603ac37a59e4477c517c9a7a799941e165d2f8ae9e587421b1550087457` |
| Family label | `unknown` |
| File name | `chrome_sample.zip` |
| File type | `zip` |
| First seen | `2026-08-19 20:49:02` |
| Reporter | `mensvr` |
| Tags | `Brazil, cryptojacker, INDIGO-SHARK, Node.js, RAT, TOR, XMRig, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb8106e3e087298db6e134d95c93ed9d` |
| SHA-1 | `b64a8dd236f45ee58a300c3e79ee3c4e45bf6db9` |
| SHA-256 | `9bf57603ac37a59e4477c517c9a7a799941e165d2f8ae9e587421b1550087457` |
| SHA3-384 | `473984a2befabf9f15c21e0ec70069405dcdba6178b734b7e944c43801737ddff8c0ed41f54ccfedc53ce62373792ecc` |
| TLSH | `T14D4733C350FFB496AD194E280E810364793A3B92B50E7EDEC7F9E86214F8C56F960635` |
| SSDEEP | `786432:07RfrkimZ+QEoaSS0rPPc8G2Np4Xtug5F:0dTkRP62PcKk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_9bf57603
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bf57603ac37a59e4477c517c9a7a799941e165d2f8ae9e587421b1550087457"
    family = "unknown"
    file_name = "chrome_sample.zip"
    file_type = "zip"
    first_seen = "2026-08-19 20:49:02"
  condition:
    hash.sha256(0, filesize) == "9bf57603ac37a59e4477c517c9a7a799941e165d2f8ae9e587421b1550087457"
}
```

### Sample 31: `367d7ffee0fb655d`

| Field | Value |
|---|---|
| SHA-256 | `367d7ffee0fb655dc63c7313ffc292b1dab6135dc41c133966a6e09d9d5e3c05` |
| Family label | `Mirai` |
| File name | `2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:46:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3477dc3cc248d97918e876580aae2bb5` |
| SHA-1 | `ac321d2c5afd6a2cb7225f98e05e43c02f637884` |
| SHA-256 | `367d7ffee0fb655dc63c7313ffc292b1dab6135dc41c133966a6e09d9d5e3c05` |
| SHA3-384 | `2bd6440f330766a7c50b99733a576d2f3056587a3793dc85ef7629ffcf9cc5704b0161c8ecd8c76b5f132126dbb41b8b` |
| TLSH | `T11C443A8A9E601FEBC4AFCD30062E831715FD999BA3F16776C67CDC48758E24846E3858` |
| TELFHASH | `t1a54141759f3598229ed2c5509ceea322e21ec5291a51ee27cf24854c006d09ef21be9f` |
| SSDEEP | `6144:JbwJ91wgzJrwwHX8YdADhGqhizPVRenu0Y/YliE:NA9fJrwwMYdkA5+nukliE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_367d7ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "367d7ffee0fb655dc63c7313ffc292b1dab6135dc41c133966a6e09d9d5e3c05"
    family = "Mirai"
    file_name = "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:46:43"
  condition:
    hash.sha256(0, filesize) == "367d7ffee0fb655dc63c7313ffc292b1dab6135dc41c133966a6e09d9d5e3c05"
}
```

### Sample 32: `1d841c5b336df35e`

| Field | Value |
|---|---|
| SHA-256 | `1d841c5b336df35e52bfec97e27a4472b53a7fd15ea9402d3fee4655a2cb8ee2` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-19 20:46:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8b6dcfa5d74937dbb06cad65d21f5cd` |
| SHA-1 | `1c3b61a51576212b3358be6dfca42b25da80337b` |
| SHA-256 | `1d841c5b336df35e52bfec97e27a4472b53a7fd15ea9402d3fee4655a2cb8ee2` |
| SHA3-384 | `9aab8d5ecef1ce84dbc8489593e15864ca261b52309eccfc93c79070aeb232d3ce8120ec7d088aca3ae7c87a1700f4f9` |
| TLSH | `T1F8F30855FC419B16CAC326B7FF4E438D77261768D3EE72039D256F20379A85A0E3A242` |
| TELFHASH | `t1ed41ef20ea5c0aac73e4c35c51de61169dac30fc3b32245a9f6dab4f0a17cd2b21e41b` |
| SSDEEP | `3072:Q8tDrcuHB5un3xVFc+TbkjJhtELqcfGV6VUhNwsAp31gtFdI0DIFzko3JHN:Q8tDrtHB5unBVFc+T+j0qE02UhNwzp3H` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_1d841c5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d841c5b336df35e52bfec97e27a4472b53a7fd15ea9402d3fee4655a2cb8ee2"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-19 20:46:03"
  condition:
    hash.sha256(0, filesize) == "1d841c5b336df35e52bfec97e27a4472b53a7fd15ea9402d3fee4655a2cb8ee2"
}
```

### Sample 33: `2bff85672c484c31`

| Field | Value |
|---|---|
| SHA-256 | `2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1` |
| Family label | `Mirai` |
| File name | `2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:45:48` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abfa84d62608452f1f6c81e04beba407` |
| SHA-1 | `420ae8a5d2863fc7767d67b3b74037b16cd9238d` |
| SHA-256 | `2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1` |
| SHA3-384 | `7c575678b1aea3f8e6016bc41f56fdc95e6ae4c3e2e72f40656242ec30d43d00713a83f49b6483d48150f8930ca8217c` |
| TLSH | `T16CD312CB9C489F3AC63ECE7C6A1E325061631F79C9E5B854D09BAC209E221AD3553787` |
| SSDEEP | `3072:ymPuoK5LzNVMaPpxB3mysqtzWts8pHfdoJ0bfMm:Y/KaTB3mMgpHfdoJwUm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_2bff8567
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1"
    family = "Mirai"
    file_name = "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:45:48"
  condition:
    hash.sha256(0, filesize) == "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1"
}
```

### Sample 34: `c43f736f1b26cf05`

| Field | Value |
|---|---|
| SHA-256 | `c43f736f1b26cf059bdb961766ddabdcc1ccde7be851b670a2f88bb67dee2dc3` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-19 20:44:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0842b27721d03541196cd7b367bc572f` |
| SHA-1 | `d3c53e0116b681c76693e6ddd428614c9488e063` |
| SHA-256 | `c43f736f1b26cf059bdb961766ddabdcc1ccde7be851b670a2f88bb67dee2dc3` |
| SHA3-384 | `8c105f3b2e7cf6094ba336042c0b1e08be2865f487b13d5117dbb0003a7ad8c83e7e968986d25b5d19fd5bf5f4c59ae3` |
| TLSH | `T1356301A392597A6ADA77233CD6EF0DE6B3328734F24374642818B1207BC1956677C4CE` |
| SSDEEP | `1536:6fadqbLINZIhanq0PaRrUVwlGJyoaeYL+W6n1pQTfkNUza:6ANPLSWVwcJyo1qFZMSm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_c43f736f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c43f736f1b26cf059bdb961766ddabdcc1ccde7be851b670a2f88bb67dee2dc3"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-19 20:44:53"
  condition:
    hash.sha256(0, filesize) == "c43f736f1b26cf059bdb961766ddabdcc1ccde7be851b670a2f88bb67dee2dc3"
}
```

### Sample 35: `f59794a0fc981089`

| Field | Value |
|---|---|
| SHA-256 | `f59794a0fc981089ed7460eb5d9cb407ad89d0bc41375a6ce9854fe38781ba76` |
| Family label | `Mirai` |
| File name | `02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:41:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16c62bbef024130dc43726a8a3dcaa2b` |
| SHA-1 | `6255ef30b148f5a559f307c9c8f416e2e661c3a2` |
| SHA-256 | `f59794a0fc981089ed7460eb5d9cb407ad89d0bc41375a6ce9854fe38781ba76` |
| SHA3-384 | `e7e139159e16f3fc4bf4a365e7c002c55122902ccc6eb4d9f198e3237ded5052d1a4341704009f364b06d0e8f539232c` |
| TLSH | `T1B4143903A5D294FEC19AC47087AFD537E93174A802317A2F6B98AF312E35E70272E351` |
| TELFHASH | `t1ce51997419967428b1b7c2167717e7affe72081052dc75a86b27b9d0be80f880cabc17` |
| SSDEEP | `3072:+8pPtHXgPC+Lww4afu5OpFIZebIJ7LzXdS793X12lU+U9t9mvvJTGql:dbHQa6wzjOpFITJHbk9klBU9t9x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_f59794a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f59794a0fc981089ed7460eb5d9cb407ad89d0bc41375a6ce9854fe38781ba76"
    family = "Mirai"
    file_name = "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:45"
  condition:
    hash.sha256(0, filesize) == "f59794a0fc981089ed7460eb5d9cb407ad89d0bc41375a6ce9854fe38781ba76"
}
```

### Sample 36: `01bc79640c037a1f`

| Field | Value |
|---|---|
| SHA-256 | `01bc79640c037a1f40086ed872caf75094ae53084dac5674b158179156c5eccd` |
| Family label | `Mirai` |
| File name | `f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:41:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7306111e6989ca864ae5f44854d2de64` |
| SHA-1 | `3df6b89443edc287ba674473c1543cf70fe82406` |
| SHA-256 | `01bc79640c037a1f40086ed872caf75094ae53084dac5674b158179156c5eccd` |
| SHA3-384 | `681f537e089149c69e0f25e026104b12e08699324953d78b3391a4d0197ef03ee4992965039dc020d21729dd873b3940` |
| TLSH | `T18D447C01FB140653D5921FB44B7B07B6E36D8A931CB4F10C6A0BBB261732E76A1DB789` |
| SSDEEP | `6144:bDEuprWFBJn93vooWIYJV3nX6GOyJiu03hHFpWX:bDED1vSVbOy2WX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_01bc7964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01bc79640c037a1f40086ed872caf75094ae53084dac5674b158179156c5eccd"
    family = "Mirai"
    file_name = "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:43"
  condition:
    hash.sha256(0, filesize) == "01bc79640c037a1f40086ed872caf75094ae53084dac5674b158179156c5eccd"
}
```

### Sample 37: `20eb4840ec929f6c`

| Field | Value |
|---|---|
| SHA-256 | `20eb4840ec929f6c8aedb2b9d74f3fce00ea789fbd8208651cba8282d67d9f33` |
| Family label | `Mirai` |
| File name | `61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:41:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c1ff3f2460e9df52fe5ff1321706128` |
| SHA-1 | `7ad0c856882eac0d9aa16b92a77bad61848eb237` |
| SHA-256 | `20eb4840ec929f6c8aedb2b9d74f3fce00ea789fbd8208651cba8282d67d9f33` |
| SHA3-384 | `6d51fef1a21a44a4362e9a4ed67e57a0690fb8ededabb60d78b86836855353e9da25fb12e6b3042893686ed5add73565` |
| TLSH | `T127148D9CAD0FBC41CBDAE3BDD9098BA2B03774B44365C0727C01136ED9AB9E6D5E2425` |
| SSDEEP | `3072:5A/Q7xnKdKwfQzdXxMZE0GN36nuzYVslX0barTO0rYdaFgERDin1xgHv18HKwSvd:kQ7xWwtjsVs90W20rYaFg11GNaK9/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_20eb4840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20eb4840ec929f6c8aedb2b9d74f3fce00ea789fbd8208651cba8282d67d9f33"
    family = "Mirai"
    file_name = "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:40"
  condition:
    hash.sha256(0, filesize) == "20eb4840ec929f6c8aedb2b9d74f3fce00ea789fbd8208651cba8282d67d9f33"
}
```

### Sample 38: `02fae52adc28a56c`

| Field | Value |
|---|---|
| SHA-256 | `02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd` |
| Family label | `Mirai` |
| File name | `02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:41:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8be3febfc837a5cdb936fab190c39d0` |
| SHA-1 | `0b85c9d40d521410d48a75a6176b73cda99a32ad` |
| SHA-256 | `02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd` |
| SHA3-384 | `2612460ef4d68cc1e6b8a220f179e72ed29d08640cf8c2aca3f59a01ca73d2080c45f2a1e9e6316381ce9b9f79fcafc3` |
| TLSH | `T113A3128D37D20DE2D0BB56F6DE5BA1CFFA07E14643088DC882D5910E695B6E2438DAF4` |
| SSDEEP | `3072:t3/6qxuBXJwwwYEcoU2oKBpXgb80Z7bDjsUEm:VxuBywYc27BpXgr9Em` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_02fae52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd"
    family = "Mirai"
    file_name = "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:01"
  condition:
    hash.sha256(0, filesize) == "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd"
}
```

### Sample 39: `f417ce91cb83439e`

| Field | Value |
|---|---|
| SHA-256 | `f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8` |
| Family label | `Mirai` |
| File name | `f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:40:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd308bccc1bd22920718de9cd9dbbd1e` |
| SHA-1 | `789b7c8d65fe7575dd97f6e52267f4507887ee93` |
| SHA-256 | `f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8` |
| SHA3-384 | `bd99ec1b472ea4e7d0be2967fcbc427d57565cf14e2e514560aaeea6cec0d8ddbe5864aa9c3af7d8022195512d7f676e` |
| TLSH | `T103B30268D7FC1005F30B2AFA957788CD93B0532A901F78E7D9526F80DFA229B9D806C5` |
| SSDEEP | `1536:KttSFqsG0qUzT213BtETu6JX7G+mEgRM1T4mZlID7icbEo3JzlG28sIFSIWoduYn:iL305zTOtku6NLT4mkj6smv2N6Rf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_f417ce91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8"
    family = "Mirai"
    file_name = "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:40:56"
  condition:
    hash.sha256(0, filesize) == "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8"
}
```

### Sample 40: `61e461992a73559c`

| Field | Value |
|---|---|
| SHA-256 | `61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d` |
| Family label | `Mirai` |
| File name | `61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:40:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c48898218a39da56847e7e97fde12837` |
| SHA-1 | `521975f2fc6004594396d5859bb850a4d9ade51c` |
| SHA-256 | `61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d` |
| SHA3-384 | `dc23ae8cbc711764704e04fdda06854ded8e201c81506bc875631b2ba00521f52c90abe4bd3c6d1e46a31151591ebcd3` |
| TLSH | `T1AFA3123D24130656F5C707B09F5BACE9641CA067EE33A035B2C13269A36D78E47A1F6B` |
| SSDEEP | `3072:Ia64w/yGIJ3sN375AQv51ZNeD8OAEiTjhCIA0gFpk:KkL3sN3eQxJq8OADgfk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_61e46199
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d"
    family = "Mirai"
    file_name = "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:40:45"
  condition:
    hash.sha256(0, filesize) == "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d"
}
```

### Sample 41: `915953d2eba9eb21`

| Field | Value |
|---|---|
| SHA-256 | `915953d2eba9eb21ee77ae729548f8529d323725946e04c08a3875cd63ca6925` |
| Family label | `unknown` |
| File name | `ziomzpihivrtvhyhayzz.exe` |
| File type | `exe` |
| First seen | `2026-08-19 20:40:08` |
| Reporter | `anonymous` |
| Tags | `clearfake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f92bdaaf20169c4c7d02f8510afb19b` |
| SHA-1 | `8bd82c3a46318180a7db889d3d3b791fc646544f` |
| SHA-256 | `915953d2eba9eb21ee77ae729548f8529d323725946e04c08a3875cd63ca6925` |
| SHA3-384 | `1cdfebd8da1e019a7d942af2a2a1f967b5aa4e6c073717d1229d9e9a6085521770f0aba63716f2337b89fd073740d00f` |
| IMPHASH | `d3d692ca53ebf794ada25d19a8f1d07d` |
| TLSH | `T12446D062BF41C071F9C202B9647E9B7A097DAE204775C0D397D43E6A88315D32B3A79B` |
| SSDEEP | `98304:EJeV/ztZBe91oiUmuUiK9N9EGQKF9lSHbr7acGpztBxdLN7:KS/hwQmg4EpbrOXztBxX` |
| ICON-DHASH | `d4e6e6d3f2bcc870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_915953d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "915953d2eba9eb21ee77ae729548f8529d323725946e04c08a3875cd63ca6925"
    family = "unknown"
    file_name = "ziomzpihivrtvhyhayzz.exe"
    file_type = "exe"
    first_seen = "2026-08-19 20:40:08"
  condition:
    hash.sha256(0, filesize) == "915953d2eba9eb21ee77ae729548f8529d323725946e04c08a3875cd63ca6925"
}
```

### Sample 42: `772568e499ecf308`

| Field | Value |
|---|---|
| SHA-256 | `772568e499ecf3080396aecdbedf27e00770888e643b724269a569ca132d2ae9` |
| Family label | `unknown` |
| File name | `sh.any` |
| File type | `exe` |
| First seen | `2026-08-19 20:39:46` |
| Reporter | `anonymous` |
| Tags | `clearfake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9bee2e47f6407c00058bbd953ba7c7a` |
| SHA-1 | `f83f005aa9958994c7f9a63dfa382ad7daf8c231` |
| SHA-256 | `772568e499ecf3080396aecdbedf27e00770888e643b724269a569ca132d2ae9` |
| SHA3-384 | `a81a7a2141f8dd0f9b117ef73282adf064370c9e7cef7c895b7cc35efc9c24142200eca1acb821be05daff4ec2a2d1c1` |
| IMPHASH | `d3d692ca53ebf794ada25d19a8f1d07d` |
| TLSH | `T1B046D062BF41C071F9C202B9647E9B7A097DAE204775C0D397D43E6A88315D32B3A79B` |
| SSDEEP | `98304:EJeV/ztZBe91oiUmuUiK9N9EGQKF9lSHbr7acGpztBxdLN0:KS/hwQmg4EpbrOXztBxQ` |
| ICON-DHASH | `d4e6e6d3f2bcc870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_772568e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "772568e499ecf3080396aecdbedf27e00770888e643b724269a569ca132d2ae9"
    family = "unknown"
    file_name = "sh.any"
    file_type = "exe"
    first_seen = "2026-08-19 20:39:46"
  condition:
    hash.sha256(0, filesize) == "772568e499ecf3080396aecdbedf27e00770888e643b724269a569ca132d2ae9"
}
```

### Sample 43: `914488444166bc2d`

| Field | Value |
|---|---|
| SHA-256 | `914488444166bc2dfd9ac9dfbc060c0dabc4b8997d07c6bb1e42cf1ee1c5ba1a` |
| Family label | `Mirai` |
| File name | `flutter.mips` |
| File type | `elf` |
| First seen | `2026-08-19 20:39:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31f08ae45d20c69e346fdd0547b57896` |
| SHA-1 | `f8996ecb8524b79cd03d6c7c029c42a6a8e59791` |
| SHA-256 | `914488444166bc2dfd9ac9dfbc060c0dabc4b8997d07c6bb1e42cf1ee1c5ba1a` |
| SHA3-384 | `0c5ba7e4ef96092ece4224a778af8d6ee6eaf1b21b8665cdb1c61d8b41f97d7767e9a05c66c1a8f58d274af657e9f107` |
| TLSH | `T112444B4B77908F91E275C97146F34AA7ABE9129327E38145E27DDE103E5038C682FFA4` |
| TELFHASH | `t1a54141759f3598229ed2c5509ceea322e21ec5291a51ee27cf24854c006d09ef21be9f` |
| SSDEEP | `6144:4qcSGAJiSPw1srwTO1IIJTZnWhoGo/i25SY4xQ1C8zknP9l/BNY+:4qF3Jg1srwTOOIJTM+P5+98onFRDv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_91448844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "914488444166bc2dfd9ac9dfbc060c0dabc4b8997d07c6bb1e42cf1ee1c5ba1a"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-08-19 20:39:39"
  condition:
    hash.sha256(0, filesize) == "914488444166bc2dfd9ac9dfbc060c0dabc4b8997d07c6bb1e42cf1ee1c5ba1a"
}
```

### Sample 44: `595d2c2250abaf70`

| Field | Value |
|---|---|
| SHA-256 | `595d2c2250abaf70cc91cd6b316966f6ba7569dcdd6c252d11d1ef374e25267b` |
| Family label | `Mirai` |
| File name | `flutter.mips` |
| File type | `elf` |
| First seen | `2026-08-19 20:38:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82e53b46ae30e398f103d33ef790cc7c` |
| SHA-1 | `e8c6a18f53e77f5116ed2154baaf33ea9563d8f4` |
| SHA-256 | `595d2c2250abaf70cc91cd6b316966f6ba7569dcdd6c252d11d1ef374e25267b` |
| SHA3-384 | `e39b00081b0b1b815a6ceafefbe582b0368c1bdbf6d8573f80ccf03565926a45b1650db8e6d0ab211e38b8a24db13654` |
| TLSH | `T1F6D312609FC8F487F86C59F7AE83348D75FB2A56E320A564F740D50CA5687C23A68A30` |
| SSDEEP | `3072:zz+KzuZQM4D7f81ekr7o8EjDJP1eAiR8T0:zSKzuZQXD736PSeApY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_595d2c22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "595d2c2250abaf70cc91cd6b316966f6ba7569dcdd6c252d11d1ef374e25267b"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-08-19 20:38:59"
  condition:
    hash.sha256(0, filesize) == "595d2c2250abaf70cc91cd6b316966f6ba7569dcdd6c252d11d1ef374e25267b"
}
```

### Sample 45: `a46966a446f1d97d`

| Field | Value |
|---|---|
| SHA-256 | `a46966a446f1d97df08bcaa347033ab4694ad19f58033fd2ba0b8bd2318cb7ed` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-19 20:36:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cb8ff2f2cb39cf003532cab6ed3064b` |
| SHA-1 | `7faf5389ac2e4b69bf77b020f134f61365a0d1b2` |
| SHA-256 | `a46966a446f1d97df08bcaa347033ab4694ad19f58033fd2ba0b8bd2318cb7ed` |
| SHA3-384 | `35fa9b804c7febb9dc482872d0bc162218ccb5fd6d5bfc30ec535f811c378edd15acbe73d362a195e717d9592c8ff99b` |
| TLSH | `T119345BA4AA0F6C42F1C2D3FCDE9C87F13A1735E3C67689B17D1203ADCAA79D95990502` |
| SSDEEP | `3072:UC60Fr/qFCszmqUhh4JPQ6XzQIJEF7JpRB1xSliMb9c3e3oq:V6YGFCsyqUhh4Jo61Ja7JjMliG3oq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_a46966a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a46966a446f1d97df08bcaa347033ab4694ad19f58033fd2ba0b8bd2318cb7ed"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-19 20:36:43"
  condition:
    hash.sha256(0, filesize) == "a46966a446f1d97df08bcaa347033ab4694ad19f58033fd2ba0b8bd2318cb7ed"
}
```

### Sample 46: `8a0e0d1bf2b530aa`

| Field | Value |
|---|---|
| SHA-256 | `8a0e0d1bf2b530aa53ca31e661a34edaf4dff95d1041dabffcac799c7f001933` |
| Family label | `Mirai` |
| File name | `46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:36:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c43ec73a4a99d77038f4e3cef403e54` |
| SHA-1 | `c329267a68cffc474a4392ded50519f059b566b0` |
| SHA-256 | `8a0e0d1bf2b530aa53ca31e661a34edaf4dff95d1041dabffcac799c7f001933` |
| SHA3-384 | `bc1024e00dd29d7831819d511ad6d49a90fdb06c5afe5d0234c6707f13f6b99d018188fd913600293e276aba4c6470e9` |
| TLSH | `T1D9F30759FD41AB10D9D62AFAFE0E028933530B78E3FE71129E245F2523CA95B0F7A505` |
| TELFHASH | `t18921e252cf480ee8b7c980a4c1fd512653ec32ee2516185aa5ace74f2da2dc5b43881f` |
| SSDEEP | `3072:Zp0Pcc8VYe1KeYYwml7i/mzYYpXOdMDmAajwTqR7R7Bdo/iN7F554hknaHYD:Zp0PcnVYOKeYYFle7AXuM6AajVR7R7BL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_8a0e0d1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a0e0d1bf2b530aa53ca31e661a34edaf4dff95d1041dabffcac799c7f001933"
    family = "Mirai"
    file_name = "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:36:41"
  condition:
    hash.sha256(0, filesize) == "8a0e0d1bf2b530aa53ca31e661a34edaf4dff95d1041dabffcac799c7f001933"
}
```

### Sample 47: `524172cff3004980`

| Field | Value |
|---|---|
| SHA-256 | `524172cff3004980870ed211cb98281964fa7d1b4f42a4bd449c549002846208` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-19 20:36:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7c3353ed3a18ce33cbcd7c6a179274d` |
| SHA-1 | `74dda54cdf52920af21db23186bb0f9bc7f6f81c` |
| SHA-256 | `524172cff3004980870ed211cb98281964fa7d1b4f42a4bd449c549002846208` |
| SHA3-384 | `54a1453454ec42751e99c290228345eb9688f1fc813149f5af3e21bcfd3ee0e7bc0d92a99680e9b5fe0bc229a7caf01b` |
| TLSH | `T124A31201DFD65FD2F4406E7C0C260663A685B72B1BA63AF7E115F7001EC1769FE812A5` |
| SSDEEP | `1536:UGIFep3BSf/XZXLFqjkcQhlDbsePeAgBqmvsIvqR6AKbUP8aPkAUSjNwAhi9iAlU:+FCBK9RQQ/Xs7vBSkTtaPkAP5zhNQc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_524172cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524172cff3004980870ed211cb98281964fa7d1b4f42a4bd449c549002846208"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-19 20:36:04"
  condition:
    hash.sha256(0, filesize) == "524172cff3004980870ed211cb98281964fa7d1b4f42a4bd449c549002846208"
}
```

### Sample 48: `46c10cf65045f2ae`

| Field | Value |
|---|---|
| SHA-256 | `46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7` |
| Family label | `Mirai` |
| File name | `46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7.elf` |
| File type | `elf` |
| First seen | `2026-08-19 20:35:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30048853bf0433b623a092a1fc8ca897` |
| SHA-1 | `4d7ef9ec4bd8e247a3bf0e8cb397dffa6936d2a0` |
| SHA-256 | `46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7` |
| SHA3-384 | `299b6ddb87e9e1042ec152397135996a7ab1dfa18ccaff4c38a15154944be21771c8c3b444304b14d99858074140973c` |
| TLSH | `T1BB630260E3ABE282D7C0077BD0F643D732E3653C606A36AA0258547FEBD02D129F519B` |
| SSDEEP | `1536:Tx7AHwI3iDaKntM3UGxboxP+qvN8LA2eBouWIiSQDLC:Tx7Jn/xPvP7piSQDLC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_46c10cf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7"
    family = "Mirai"
    file_name = "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:35:44"
  condition:
    hash.sha256(0, filesize) == "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7"
}
```

### Sample 49: `24fdc48249a04de2`

| Field | Value |
|---|---|
| SHA-256 | `24fdc48249a04de295cbcc222a9da62ecffdf60cee25c3879bf12ccab3393282` |
| Family label | `DCRat` |
| File name | `19218b199b1706d1e1f4416ffb1b27cf.exe` |
| File type | `exe` |
| First seen | `2026-08-19 20:35:09` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19218b199b1706d1e1f4416ffb1b27cf` |
| SHA-1 | `b61cb466e36c1a047159ced3f2317ba189940af3` |
| SHA-256 | `24fdc48249a04de295cbcc222a9da62ecffdf60cee25c3879bf12ccab3393282` |
| SHA3-384 | `990fac27dfa2255d642a1f5be1e610e04625a12eafc6ceef3ec40ebda34fb01e2c3eadd8ff51ce9e5cf72238d7ffcadf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1650508417E44CE01F0095A33C2EF55488BB09D5166AAE32B7DBE37AE25123977C0DADB` |
| SSDEEP | `12288:Udr6HUM9ev4KM7FNj5UDjyq6M273IDf+Wz64Zjj9AArt65:Ud4UM9iMJNjG38CDfz64ZX9DE5` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_049_24fdc482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24fdc48249a04de295cbcc222a9da62ecffdf60cee25c3879bf12ccab3393282"
    family = "DCRat"
    file_name = "19218b199b1706d1e1f4416ffb1b27cf.exe"
    file_type = "exe"
    first_seen = "2026-08-19 20:35:09"
  condition:
    hash.sha256(0, filesize) == "24fdc48249a04de295cbcc222a9da62ecffdf60cee25c3879bf12ccab3393282"
}
```

### Sample 50: `41097031ebd7827a`

| Field | Value |
|---|---|
| SHA-256 | `41097031ebd7827a60bac14e80a4032f00d11a1d3f0bdb2e0aea7e0a5bd69d00` |
| Family label | `Mirai` |
| File name | `flutter.arm7` |
| File type | `elf` |
| First seen | `2026-08-19 20:30:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf05ec35072306aeba3fcfdc96cb858a` |
| SHA-1 | `8a96e603ea2323caab6fbd7a63170596ee7d9329` |
| SHA-256 | `41097031ebd7827a60bac14e80a4032f00d11a1d3f0bdb2e0aea7e0a5bd69d00` |
| SHA3-384 | `32d707add932660a1e7c93fdec0f82c55b1813aa23185a0cc336bf3a328485a8aeb6ffa842f12d1f3494342e4775ba19` |
| TLSH | `T1DD041956F880DE66C6D1267AFA9D429C331317B8D3DA7002DD206F2937EB45E0B3E646` |
| SSDEEP | `3072:EOzJmJP9VRmduC2f9vzdkE6nQXrl1bDwymSyG71ik79GIOID5Cw4zzJIztRJkRSy:EcJmVp6nQbl1bDw3u1ilIO25Cw4zzJI+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_41097031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41097031ebd7827a60bac14e80a4032f00d11a1d3f0bdb2e0aea7e0a5bd69d00"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-08-19 20:30:58"
  condition:
    hash.sha256(0, filesize) == "41097031ebd7827a60bac14e80a4032f00d11a1d3f0bdb2e0aea7e0a5bd69d00"
}
```

### Sample 51: `b6485bb24becb01d`

| Field | Value |
|---|---|
| SHA-256 | `b6485bb24becb01de3319bc543c026f2b22695146dca3447143384ed92f6933a` |
| Family label | `Mirai` |
| File name | `flutter.arm7` |
| File type | `elf` |
| First seen | `2026-08-19 20:29:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c86389a6a96f84218d807c611373698` |
| SHA-1 | `7e5f7077a94a366f70f73961ca9a2b68d2ec2315` |
| SHA-256 | `b6485bb24becb01de3319bc543c026f2b22695146dca3447143384ed92f6933a` |
| SHA3-384 | `fee5a317b159e43866e7d25c0f3512102831eeb45db5edd0faaf7355187cea9207ed3cef87b6e562639abc60c519a217` |
| TLSH | `T1EDA3022C67209251D937E7784E9D87626F0107F8810CB99B7DD669926F370CE824F6BC` |
| SSDEEP | `1536:XzVsP015JkwX/cI74I319F4HbWI6wsoTvD0Un6DcIBbM/O1tws4Myv+P:Xze4JRv14I319F4iI0oT2BKO1tws4e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_b6485bb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6485bb24becb01de3319bc543c026f2b22695146dca3447143384ed92f6933a"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-08-19 20:29:51"
  condition:
    hash.sha256(0, filesize) == "b6485bb24becb01de3319bc543c026f2b22695146dca3447143384ed92f6933a"
}
```

### Sample 52: `44fe967dbea22001`

| Field | Value |
|---|---|
| SHA-256 | `44fe967dbea2200187ed5859ee13fbd27a0c4d51bca120d7715246f2f866b13c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-19 20:29:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8194719b4eeb37796f47cc8245911de4` |
| SHA-1 | `ce05d29da716b74f36ba568545620cf313261eac` |
| SHA-256 | `44fe967dbea2200187ed5859ee13fbd27a0c4d51bca120d7715246f2f866b13c` |
| SHA3-384 | `53ed031501aa5db07f1e9b83f885bb854a0ad76aed5f91e3e7bed5b41c9ed4a302cf7f5601704edcee104ca3b5efd101` |
| TLSH | `T12FC27D956A867C44BDC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B2A` |
| SSDEEP | `768:aZ8vCB+25j6es8Ron9FYpMSUpi+20qUpi+20YQX:aZ8l25Jid2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_44fe967d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44fe967dbea2200187ed5859ee13fbd27a0c4d51bca120d7715246f2f866b13c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-19 20:29:49"
  condition:
    hash.sha256(0, filesize) == "44fe967dbea2200187ed5859ee13fbd27a0c4d51bca120d7715246f2f866b13c"
}
```

### Sample 53: `d684fb1e82d42041`

| Field | Value |
|---|---|
| SHA-256 | `d684fb1e82d42041802c676440d58e964b19ae74e8e7669e84d15da1a1e9c7ee` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-19 20:25:53` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX1.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4992d7be027533fc672270754604b7d6` |
| SHA-1 | `1703b38af406c38f7a13972473968597377aa4e4` |
| SHA-256 | `d684fb1e82d42041802c676440d58e964b19ae74e8e7669e84d15da1a1e9c7ee` |
| SHA3-384 | `e14ac1924ab8c2193eed327f15137a044e38af989e63d2377da14e5db1285b629a7fede6a7bc9da9dd30a3e35cc51408` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T15FE549077E4451A5C09AAB39E4B70153BA31BC4CCB3673E76E909A742F727C1ADB2B14` |
| SSDEEP | `24576:i+EeP8NuF+2I5a1aqU0zPg132WtFMiXGzHAZ1+L/BLolHycYmoRgjtz2n:3hP8NoIQK0zPg132CMi+AZ1+7hqegNa` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_053_d684fb1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d684fb1e82d42041802c676440d58e964b19ae74e8e7669e84d15da1a1e9c7ee"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 20:25:53"
  condition:
    hash.sha256(0, filesize) == "d684fb1e82d42041802c676440d58e964b19ae74e8e7669e84d15da1a1e9c7ee"
}
```

### Sample 54: `db0ef37f0a87b9ab`

| Field | Value |
|---|---|
| SHA-256 | `db0ef37f0a87b9abb1affd3a5644f90b9cfa0062990f8bf80d6dcbd23c4e89cb` |
| Family label | `Mirai` |
| File name | `flutter.arm` |
| File type | `elf` |
| First seen | `2026-08-19 20:24:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd51bd770b346bf902c6af8a0dcd01d6` |
| SHA-1 | `da0153c77793b96d710003141748ebd81ba4a9d2` |
| SHA-256 | `db0ef37f0a87b9abb1affd3a5644f90b9cfa0062990f8bf80d6dcbd23c4e89cb` |
| SHA3-384 | `c3eb47b3ea8674ffbc1bd7c7753573d6b90cd233bba463364603afeddb9f8dc333e8b3fbb9e9fb7406c0983685e6143a` |
| TLSH | `T104042995F8809F66D6D1267AFA9D018C33131778D3DAB102DD20AF3537EB95E0A3E942` |
| SSDEEP | `3072:m5OUFc/xBtLduC2RlL6yIV7BWwbTOhwd5g8VI1kqeRXOAH4DSkNymAgWXB985aV2:kOalL6yIxkwbTOhS5g8eaZRXOAH4DSkb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_db0ef37f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db0ef37f0a87b9abb1affd3a5644f90b9cfa0062990f8bf80d6dcbd23c4e89cb"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-08-19 20:24:43"
  condition:
    hash.sha256(0, filesize) == "db0ef37f0a87b9abb1affd3a5644f90b9cfa0062990f8bf80d6dcbd23c4e89cb"
}
```

### Sample 55: `9bc7123d4912de9a`

| Field | Value |
|---|---|
| SHA-256 | `9bc7123d4912de9adba9f10d87b1bc1224f5059d730eb7489cb96f07e6a7d37f` |
| Family label | `Mirai` |
| File name | `flutter.arm` |
| File type | `elf` |
| First seen | `2026-08-19 20:24:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8902fee97641dca236738e5451b2c0e3` |
| SHA-1 | `26196bf7b01c1f16dbc5972e845c95aa94fd1af5` |
| SHA-256 | `9bc7123d4912de9adba9f10d87b1bc1224f5059d730eb7489cb96f07e6a7d37f` |
| SHA3-384 | `e078d40b80105d126e5eb3c9d37c3279ba08dbef32ab35bdb4cde2f7212c106bcc42fea5ae18f1c4def334215f0de13f` |
| TLSH | `T1B7A3010AD3A39C5AE5E998B0E88E627D07085FC85D9D634B0D52D0BC29D3B217F69287` |
| SSDEEP | `3072:wYxHyuveMsVLuJdUzwsDD9JhOT4uH3Iz5f:zS6wXzwsDxOU5f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_9bc7123d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bc7123d4912de9adba9f10d87b1bc1224f5059d730eb7489cb96f07e6a7d37f"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-08-19 20:24:04"
  condition:
    hash.sha256(0, filesize) == "9bc7123d4912de9adba9f10d87b1bc1224f5059d730eb7489cb96f07e6a7d37f"
}
```

### Sample 56: `907103c82012064f`

| Field | Value |
|---|---|
| SHA-256 | `907103c82012064f629d1ff30afa1277a4b9f4e2d637060a2b917ec5413585f6` |
| Family label | `unknown` |
| File name | `a.sh` |
| File type | `sh` |
| First seen | `2026-08-19 20:24:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49a2212eb246ea7427eb5fdb58d44c1f` |
| SHA-1 | `ec7757f2102ed7195a5bae31e5b50853ec57b19c` |
| SHA-256 | `907103c82012064f629d1ff30afa1277a4b9f4e2d637060a2b917ec5413585f6` |
| SHA3-384 | `084201fbbc8c2e88925a692fc70c7df79cf4532547bbc10473f57a1e04b69f095e9a848eee195b9be8d9c01ee498b55c` |
| TLSH | `T11E1112FD35622F32E3964E89F1609634B30BE9D9E6CF23C1B5071963DC566407A4B911` |
| SSDEEP | `24:5XFBueBCBS0BmdBSQBQBjbMtGpuiGpIGprHGp0GpzHGpan:gIr+pMt0ui0I0rH000zH0an` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_907103c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "907103c82012064f629d1ff30afa1277a4b9f4e2d637060a2b917ec5413585f6"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-08-19 20:24:03"
  condition:
    hash.sha256(0, filesize) == "907103c82012064f629d1ff30afa1277a4b9f4e2d637060a2b917ec5413585f6"
}
```

### Sample 57: `deb1a4ed15b00fa6`

| Field | Value |
|---|---|
| SHA-256 | `deb1a4ed15b00fa6f2ee706cd9aae50d8bd8a5efda0a608e27fc4bb05c0972c9` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-08-19 20:21:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c56a82a49a0c5ff8a51510cc762fc88` |
| SHA-1 | `4cb201c46f24f53f2eafef9bf40bc3c63bcbbb81` |
| SHA-256 | `deb1a4ed15b00fa6f2ee706cd9aae50d8bd8a5efda0a608e27fc4bb05c0972c9` |
| SHA3-384 | `fb024aa5becab5ba122bccc0479321f70dad0c144bab3d7037ecdb25d343bc73fa0365cb647ac61b1deaa2451f176149` |
| TLSH | `T1F204BFABB30B2C60D86002F41FCB5B9C2AEB61454D6BD9E36C7D763A25774DE28063D1` |
| SSDEEP | `3072:tpvCzPgNThqIAqqSqRKWgmutF8uoa3qfPrJUq8uIgVCPnaCPEk7bHyq:zvCzehoXKrtqaaH9UTunCPa8Exq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_deb1a4ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deb1a4ed15b00fa6f2ee706cd9aae50d8bd8a5efda0a608e27fc4bb05c0972c9"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-19 20:21:07"
  condition:
    hash.sha256(0, filesize) == "deb1a4ed15b00fa6f2ee706cd9aae50d8bd8a5efda0a608e27fc4bb05c0972c9"
}
```

### Sample 58: `fe4ff488b8958f33`

| Field | Value |
|---|---|
| SHA-256 | `fe4ff488b8958f33957264ae55a15bfd5640b495355e13db95275a9ddb7dbbd6` |
| Family label | `unknown` |
| File name | `b.py` |
| File type | `unknown` |
| First seen | `2026-08-19 20:20:00` |
| Reporter | `juroots` |
| Tags | `py` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `883f84b85334e33d6f73eb50b96ca99e` |
| SHA-256 | `fe4ff488b8958f33957264ae55a15bfd5640b495355e13db95275a9ddb7dbbd6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_fe4ff488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe4ff488b8958f33957264ae55a15bfd5640b495355e13db95275a9ddb7dbbd6"
    family = "unknown"
    file_name = "b.py"
    file_type = "unknown"
    first_seen = "2026-08-19 20:20:00"
  condition:
    hash.sha256(0, filesize) == "fe4ff488b8958f33957264ae55a15bfd5640b495355e13db95275a9ddb7dbbd6"
}
```

### Sample 59: `d7fb753535b2a343`

| Field | Value |
|---|---|
| SHA-256 | `d7fb753535b2a343489b29aa769b9550da565c5d91b99e56f04852d8e7290585` |
| Family label | `Mirai` |
| File name | `flutter.x86` |
| File type | `elf` |
| First seen | `2026-08-19 20:18:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bde254ee826bc4c8c832431e7c85284d` |
| SHA-1 | `5135c0218fdee9299c66875cd338177ca8c8fdd7` |
| SHA-256 | `d7fb753535b2a343489b29aa769b9550da565c5d91b99e56f04852d8e7290585` |
| SHA3-384 | `b772f7b7cf782e20a0bd2a7f595cc6d9055a3c31de734ce3cf222d7f651171845db480c281d4baaa728f4edebe3a2dc8` |
| TLSH | `T1B6046C1BEA42E170E0738071514AD7739635A9314306C807FBA63F35EDB46C5E68AB6E` |
| SSDEEP | `3072:+zO7iih3bFu/+AM8Gsb0wtxhtuMkqK3NpX7evtrwC+usQTaXMTROiXavvJs:+zEiKuxMW0cxhtuMPshuRSkOc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_d7fb7535
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7fb753535b2a343489b29aa769b9550da565c5d91b99e56f04852d8e7290585"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-19 20:18:37"
  condition:
    hash.sha256(0, filesize) == "d7fb753535b2a343489b29aa769b9550da565c5d91b99e56f04852d8e7290585"
}
```

### Sample 60: `8a7c4e39d1818981`

| Field | Value |
|---|---|
| SHA-256 | `8a7c4e39d1818981f48bcb7537136da3a358156b2521728fc4108dd86b1c6c82` |
| Family label | `Mirai` |
| File name | `flutter.x86` |
| File type | `elf` |
| First seen | `2026-08-19 20:17:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50ee36656e9ad14c3953bc6bb254cb91` |
| SHA-1 | `139d561ec063d71bf124f448f12176e6335ef980` |
| SHA-256 | `8a7c4e39d1818981f48bcb7537136da3a358156b2521728fc4108dd86b1c6c82` |
| SHA3-384 | `f104d2443189e3d8ddab208c784fe89149d63216712da0041c3383dfc58db1f0e4c10a70dd7626d37c8d63a861c23e03` |
| TLSH | `T180A3131A4A6E053BE05E3F36F1B43DEA3F125218DA6D6718577F8B0171A6C4D08453AF` |
| SSDEEP | `1536:G9m2X9xpzALqQpfDrSUK0q28ohArZWr7XqEQwiu1Yh1hY6zDRDAoIL0sUtQB/Tpi:P2Xbpzs/o0q2Ye7b1YmoRMoILOcZtAWm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_8a7c4e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a7c4e39d1818981f48bcb7537136da3a358156b2521728fc4108dd86b1c6c82"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-19 20:17:56"
  condition:
    hash.sha256(0, filesize) == "8a7c4e39d1818981f48bcb7537136da3a358156b2521728fc4108dd86b1c6c82"
}
```

### Sample 61: `fcb7a789e1211bda`

| Field | Value |
|---|---|
| SHA-256 | `fcb7a789e1211bda2c3e6e55d1fb0f69f7b86e376569a3da6502054573c93f82` |
| Family label | `Mirai` |
| File name | `flutter.m68k` |
| File type | `elf` |
| First seen | `2026-08-19 20:14:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9a6f5e3b23044bbe3b1c0f539443b7d` |
| SHA-1 | `fee70e42e46ee42d46de7aa3c7d033f3cd09dfea` |
| SHA-256 | `fcb7a789e1211bda2c3e6e55d1fb0f69f7b86e376569a3da6502054573c93f82` |
| SHA3-384 | `c59e8d853928587c234f5bd5af443ad80a3c9051f021f85028c9f08691feadb1051b18144af6c33242d8b444ffadf4ef` |
| TLSH | `T12D047CC571483D6FE6D33F3EC55855279C0C8B57A8834A2250AAFE830BB74A71F3694A` |
| TELFHASH | `t15bf0dfb25fb03a230984cd08c0f76375b06ee489058afc07d340082c00e801fb21bd1f` |
| SSDEEP | `3072:FZWv9mwnO+3ZunCI9tfUd5thpszfyv0yZRpqia4svLftcGavvqWoeU:FZW1m6O6Z/6Ud5npszfgpZ3qiGvLVc8Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_fcb7a789
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcb7a789e1211bda2c3e6e55d1fb0f69f7b86e376569a3da6502054573c93f82"
    family = "Mirai"
    file_name = "flutter.m68k"
    file_type = "elf"
    first_seen = "2026-08-19 20:14:47"
  condition:
    hash.sha256(0, filesize) == "fcb7a789e1211bda2c3e6e55d1fb0f69f7b86e376569a3da6502054573c93f82"
}
```

### Sample 62: `7869ebdc68d79aaa`

| Field | Value |
|---|---|
| SHA-256 | `7869ebdc68d79aaa51b73b417d5d6a107ae355761b91f4303c388f4635ff8481` |
| Family label | `unknown` |
| File name | `HCGFhPaIrP.vbs` |
| File type | `vbs` |
| First seen | `2026-08-19 20:13:59` |
| Reporter | `mensvr` |
| Tags | `Brazil, cryptojacker, INDIGO-SHARK, Node.js, RAT, TOR, vbs, XMRig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fad588ae21e0cceab91b6debc5a70d2` |
| SHA-1 | `498b82eb5334d47950af78246012600872cc9088` |
| SHA-256 | `7869ebdc68d79aaa51b73b417d5d6a107ae355761b91f4303c388f4635ff8481` |
| SHA3-384 | `238ce9f1a4c8dee19c45bf6279753abe8a26c99ccc5a09e96bb8a5b8c78b56acfbee9c2cf4f2b91f76a0016007bfe0b6` |
| TLSH | `T19BB012119113C3A1F1534FD2D86A83DE91A528C20C5CE3155A91C0DD41BBAB40B453C9` |
| SSDEEP | `3:YwAuAEFx7D/ecP2RTukVUwg0TKldRHjh6C:YwTAA7yG2Rifwx8Hjhv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_7869ebdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7869ebdc68d79aaa51b73b417d5d6a107ae355761b91f4303c388f4635ff8481"
    family = "unknown"
    file_name = "HCGFhPaIrP.vbs"
    file_type = "vbs"
    first_seen = "2026-08-19 20:13:59"
  condition:
    hash.sha256(0, filesize) == "7869ebdc68d79aaa51b73b417d5d6a107ae355761b91f4303c388f4635ff8481"
}
```

### Sample 63: `3ed960da28f701de`

| Field | Value |
|---|---|
| SHA-256 | `3ed960da28f701deef8733e265a63a9471612611abdfc1b5e417617a744e5416` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-19 20:06:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `717d375d8f5da5b0c1cc84c49f23ac3a` |
| SHA-1 | `49e53b81e83ece69879553f66f607a7e2116d1c4` |
| SHA-256 | `3ed960da28f701deef8733e265a63a9471612611abdfc1b5e417617a744e5416` |
| SHA3-384 | `9db52fb0d3bce33d5ece5b53c3ad0dedfc1ea0e04e169479b270b38f164efb8cb01c8691dcf27ce409b621ed27a2c534` |
| TLSH | `T149446D45AF606EFBC42ECE31052EC30A21DD589BA2F5B73AB578CD4CB96A30915F3854` |
| TELFHASH | `t19a4123f04e3bda0ada99caec89fdab6e780f54165219cf23ed30406d40510f9e25ad5f` |
| SSDEEP | `6144:MGboAkp/fkLXGPmuLyb3kxdSGvYiY2xUrgzSu1xRm+M8ThZ:M0oiIlWb3kxdSG3euk+fD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_3ed960da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ed960da28f701deef8733e265a63a9471612611abdfc1b5e417617a744e5416"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-19 20:06:34"
  condition:
    hash.sha256(0, filesize) == "3ed960da28f701deef8733e265a63a9471612611abdfc1b5e417617a744e5416"
}
```

### Sample 64: `8dfc0d4d63533847`

| Field | Value |
|---|---|
| SHA-256 | `8dfc0d4d635338474f65c1c6aaecd9238761a669179d9bfc70341e5c8b7ae6c5` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-19 20:06:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff291fb408afc5129efadfe13a780802` |
| SHA-1 | `bd86991fc12e05d06bda1a3b218a191437d74713` |
| SHA-256 | `8dfc0d4d635338474f65c1c6aaecd9238761a669179d9bfc70341e5c8b7ae6c5` |
| SHA3-384 | `e5e5da87b00e211826bf610af2c280a183c2376fa0cf5455c57cf0040b78a23d3ca28677e692de8a78fd90b3918a4233` |
| TLSH | `T17CD31270AC00C2C4CA5B7D315B54BEEE9C3B857DA9F98A13D285895C1A664DF3B140FB` |
| SSDEEP | `3072:wUhYgLxuzN9HoKKGthKSfkc9bEsgPVMkMXnui2n4C6j3IG0x:wzrvIKKGthK+kibETzM+GrIGw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_8dfc0d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dfc0d4d635338474f65c1c6aaecd9238761a669179d9bfc70341e5c8b7ae6c5"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-19 20:06:15"
  condition:
    hash.sha256(0, filesize) == "8dfc0d4d635338474f65c1c6aaecd9238761a669179d9bfc70341e5c8b7ae6c5"
}
```

### Sample 65: `622ad8a0eb9290c6`

| Field | Value |
|---|---|
| SHA-256 | `622ad8a0eb9290c6c1fb7924f6019e18b34fee8b7583d756f1c8750ed6e793e8` |
| Family label | `njrat` |
| File name | `15d1b26149fde69fc4203df9dfb6f220.exe` |
| File type | `exe` |
| First seen | `2026-08-19 20:00:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15d1b26149fde69fc4203df9dfb6f220` |
| SHA-1 | `bf2b4974db62c18a5c83ce2f86ddbf1d89b2a030` |
| SHA-256 | `622ad8a0eb9290c6c1fb7924f6019e18b34fee8b7583d756f1c8750ed6e793e8` |
| SHA3-384 | `353e4f21ab3e2a0cb927bfef0b323ff35d5b8240d24a2ce04ce74646a0f9b9918cd38b119681804dadb322d428a39576` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T171D2D11521F90616CA774BFE39E741B113FA7948AC77CD2E58788C1B6A093AF4C017B8` |
| SSDEEP | `768:J225M5U7Em4veab83XldBboRpYkQNg4JptE:J22V7Etv9eXZogkQO4Jpm` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_065_622ad8a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "622ad8a0eb9290c6c1fb7924f6019e18b34fee8b7583d756f1c8750ed6e793e8"
    family = "njrat"
    file_name = "15d1b26149fde69fc4203df9dfb6f220.exe"
    file_type = "exe"
    first_seen = "2026-08-19 20:00:11"
  condition:
    hash.sha256(0, filesize) == "622ad8a0eb9290c6c1fb7924f6019e18b34fee8b7583d756f1c8750ed6e793e8"
}
```

### Sample 66: `3e7333a7d765a027`

| Field | Value |
|---|---|
| SHA-256 | `3e7333a7d765a0277a04617c0ed54d2e79ef50e6787462e648a724981218021a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-19 19:59:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b4d017b5d32741a16f2b1997d30c742` |
| SHA-1 | `29910d6b65cd5bdafdf5406ca9e43533ee0b47f7` |
| SHA-256 | `3e7333a7d765a0277a04617c0ed54d2e79ef50e6787462e648a724981218021a` |
| SHA3-384 | `6aa470e59eb5b205cf4440bdf56bc92ccee36ce0e892d49aa6bb4dea158d077582c3651877a97bb36c718cce0c3efee7` |
| TLSH | `T137C27D966A867C44BEC98A3E4CBD2B0D6DF5C3D1324942AC3D4A3C719C11FACD618B1A` |
| SSDEEP | `768:U8vCB+25j6es8R+99FYpMSUpi+20qUpi+20YQX:U8l25J+rd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_3e7333a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e7333a7d765a0277a04617c0ed54d2e79ef50e6787462e648a724981218021a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-19 19:59:46"
  condition:
    hash.sha256(0, filesize) == "3e7333a7d765a0277a04617c0ed54d2e79ef50e6787462e648a724981218021a"
}
```

### Sample 67: `77ea6c1d964d7bf9`

| Field | Value |
|---|---|
| SHA-256 | `77ea6c1d964d7bf9a1bdb5a7a34b6f707065235554ff7fc58dd2de2def70c53a` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-19 19:57:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f712622c612688ef0f208f9c9fc4220d` |
| SHA-1 | `02a40d6c78d45f59f7e12508b06c84614ae19615` |
| SHA-256 | `77ea6c1d964d7bf9a1bdb5a7a34b6f707065235554ff7fc58dd2de2def70c53a` |
| SHA3-384 | `a225dba0dd50b09917ad2325ae7af592107d95f9f85c9e12d9c57bee00c5daa69ec384a460963ac5b2ffae3b5f414dba` |
| TLSH | `T1ADC35C46F783E0F0D94606B1006BF7394A35DD725025DE9BEBE4FD76AD32602A20A76C` |
| TELFHASH | `t1615129babae50cd86bd00812e24a6751dd18773f64107ab70bb2585837b3b51617bc3c` |
| SSDEEP | `3072:TB0Ie75yLuIi27mS9bB8RcDqhWTToeFmz/C1NdqKVR7:te75ySI8S9bB8NoT/ZV7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_77ea6c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77ea6c1d964d7bf9a1bdb5a7a34b6f707065235554ff7fc58dd2de2def70c53a"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-19 19:57:39"
  condition:
    hash.sha256(0, filesize) == "77ea6c1d964d7bf9a1bdb5a7a34b6f707065235554ff7fc58dd2de2def70c53a"
}
```

### Sample 68: `5bb9a2335169cf82`

| Field | Value |
|---|---|
| SHA-256 | `5bb9a2335169cf8237cfa2e254340d6475788a091dd9be2e3a690e018fcb7ef0` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-19 19:56:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11c4250a55095c6a6ab09619cd2c49fc` |
| SHA-1 | `ba9baa6e54699ce7d47030a7dde1691e0bf2063b` |
| SHA-256 | `5bb9a2335169cf8237cfa2e254340d6475788a091dd9be2e3a690e018fcb7ef0` |
| SHA3-384 | `db1582dec3ac7a7fde462346ab8347773c6cf881bd55ceac0574ad2ea785c5514d04c1ffa1228b41e338c9db9d655841` |
| TLSH | `T1B553029BB0F22D70ECB749B90C9E34A98E14C71EE44760D1EED6217FE54A66E43216F0` |
| SSDEEP | `1536:LhDrR20D0KBoOyT6N4/EJg9+Duaynouy8Lzkk+:m0D0KBo44sJC+DuaqoutUk+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_5bb9a233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb9a2335169cf8237cfa2e254340d6475788a091dd9be2e3a690e018fcb7ef0"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-19 19:56:52"
  condition:
    hash.sha256(0, filesize) == "5bb9a2335169cf8237cfa2e254340d6475788a091dd9be2e3a690e018fcb7ef0"
}
```

### Sample 69: `a7a3591258756996`

| Field | Value |
|---|---|
| SHA-256 | `a7a3591258756996e1e0a2a8dd1722cd8d5f741c0ce5492dba1eebc0e52dfa32` |
| Family label | `unknown` |
| File name | `ziomzpihivrtvhyhayzz.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:50:01` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4d29ad0704c5e02d389d3fccef359db` |
| SHA-1 | `da0b4bc8fb4e4c0240c6704ab8afd27baaaec423` |
| SHA-256 | `a7a3591258756996e1e0a2a8dd1722cd8d5f741c0ce5492dba1eebc0e52dfa32` |
| SHA3-384 | `a793442c901d2925aa38784f43c76b0fe5578048737db8bfd6fd70a9d39fa32c42d17383867908ae832c8f6e3df45fbe` |
| IMPHASH | `d3d692ca53ebf794ada25d19a8f1d07d` |
| TLSH | `T1A046D062BF41C071F9C202B9647E9B7A097DAE204775C0D397D43E6A88315D32B3A79B` |
| SSDEEP | `98304:EJeV/ztZBe91oiUmuUiK9N9EGQKF9lSHbr7acGpztBxdLN/:KS/hwQmg4EpbrOXztBxz` |
| ICON-DHASH | `d4e6e6d3f2bcc870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_a7a35912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7a3591258756996e1e0a2a8dd1722cd8d5f741c0ce5492dba1eebc0e52dfa32"
    family = "unknown"
    file_name = "ziomzpihivrtvhyhayzz.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:50:01"
  condition:
    hash.sha256(0, filesize) == "a7a3591258756996e1e0a2a8dd1722cd8d5f741c0ce5492dba1eebc0e52dfa32"
}
```

### Sample 70: `87e6859c66447242`

| Field | Value |
|---|---|
| SHA-256 | `87e6859c66447242daaf9e0fa55d608bce1c572082e2e0d117d81a13663fc318` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-19 19:38:03` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39209225a7f2831f5f7c65609c62e924` |
| SHA-1 | `c195a5cbea580a1eae7fbb5845bcf32653a4a5be` |
| SHA-256 | `87e6859c66447242daaf9e0fa55d608bce1c572082e2e0d117d81a13663fc318` |
| SHA3-384 | `8fa78950badd70c2b53e1cdd3f843da9e012d948d6b30e15092bb45323797d832c7bf355f802c1140c2c235eb1499b5d` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1AD165B03AEA940F1C45AEB3895BA56857630FC4A873433F73EA1BA703F657E559B4B00` |
| SSDEEP | `24576:oYRJcX3llp+7yteghmrFyNvy7E3xYXFvDMD+XubCVUou7DOk08c0bKcVFmdTJx+O:JJcH3g7ytHwrY32XRMDcS50XjX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_87e6859c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87e6859c66447242daaf9e0fa55d608bce1c572082e2e0d117d81a13663fc318"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 19:38:03"
  condition:
    hash.sha256(0, filesize) == "87e6859c66447242daaf9e0fa55d608bce1c572082e2e0d117d81a13663fc318"
}
```

### Sample 71: `5c1f8f839d1d3335`

| Field | Value |
|---|---|
| SHA-256 | `5c1f8f839d1d333582b71afb3b7e64bf5d9be450dfeee1fcdb4b0ead017c5bc2` |
| Family label | `unknown` |
| File name | `Toolkit_v12.5.zip` |
| File type | `zip` |
| First seen | `2026-08-19 19:29:47` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b91b8490d7e4b603c496f8e71b62f1f7` |
| SHA-1 | `73072df887188a69c4901511ffde2f370114528e` |
| SHA-256 | `5c1f8f839d1d333582b71afb3b7e64bf5d9be450dfeee1fcdb4b0ead017c5bc2` |
| SHA3-384 | `5dd2b0d86a8c236732d977df0be114a9b1d6225db0736f0147d919f48af8bede4b3134486cd5bbe83bd5b2b88c30b49c` |
| TLSH | `T1703733246039499FCA93733C305A1613CC9EDBCDF964FE15A95607CA9D9BFD20F0268A` |
| SSDEEP | `393216:mnpGmckB2X46FrVtzfZ3wYVKYTlG5VwkFBXfZn1pEsCOaT:epGVkMrzqJK8BXfZDpCOQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_5c1f8f83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c1f8f839d1d333582b71afb3b7e64bf5d9be450dfeee1fcdb4b0ead017c5bc2"
    family = "unknown"
    file_name = "Toolkit_v12.5.zip"
    file_type = "zip"
    first_seen = "2026-08-19 19:29:47"
  condition:
    hash.sha256(0, filesize) == "5c1f8f839d1d333582b71afb3b7e64bf5d9be450dfeee1fcdb4b0ead017c5bc2"
}
```

### Sample 72: `43f1cf9805469018`

| Field | Value |
|---|---|
| SHA-256 | `43f1cf980546901863c625ab3fa04961b720167421f78fe6558b204cf081f826` |
| Family label | `unknown` |
| File name | `XML Files.zip` |
| File type | `zip` |
| First seen | `2026-08-19 19:20:44` |
| Reporter | `UCPGoA23` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40b4df2d93673222d07e5380c05bcc57` |
| SHA-1 | `d2ddb01d5bdb9d2a15fead11392b5c63a23a0dd4` |
| SHA-256 | `43f1cf980546901863c625ab3fa04961b720167421f78fe6558b204cf081f826` |
| SHA3-384 | `fa8220d6b8a9d266713ffb59486b54cb2891ac4b83e4acc0c3b4a2e070144c77f36c47c88eb3d52200d720601d30f67d` |
| TLSH | `T165D533D0A07BA719CCB78171D483810C8BC79A17D776486D3F955C84E6290ABAB73FB2` |
| SSDEEP | `49152:MjSjLhqTU4qTULygqhUuAO6KPlGWR0ko8lNt1vGcrRwLPvAFVF1F1Fe/JJlLthiV:Amz9GuFlGy0ko8/t1vGcrRwLPoFVF1FX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_43f1cf98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43f1cf980546901863c625ab3fa04961b720167421f78fe6558b204cf081f826"
    family = "unknown"
    file_name = "XML Files.zip"
    file_type = "zip"
    first_seen = "2026-08-19 19:20:44"
  condition:
    hash.sha256(0, filesize) == "43f1cf980546901863c625ab3fa04961b720167421f78fe6558b204cf081f826"
}
```

### Sample 73: `e61ada7705acfb83`

| Field | Value |
|---|---|
| SHA-256 | `e61ada7705acfb837faa1fd96bc3f733ee174a3562e423ccd2707ddb15cccb8f` |
| Family label | `unknown` |
| File name | `spxploy.vbs` |
| File type | `vbs` |
| First seen | `2026-08-19 19:13:45` |
| Reporter | `juroots` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `367b186e5576335a38aeba7b2e9c06d8` |
| SHA-1 | `d00feae45f9095366eb38060b4b4102cf0fe5f5e` |
| SHA-256 | `e61ada7705acfb837faa1fd96bc3f733ee174a3562e423ccd2707ddb15cccb8f` |
| SHA3-384 | `7eb2df3eb194b33af1d4f595b213fc7241619136426a5158af8f4070415cca3ac59c9ecf94cea1f43ab3164ceb1be156` |
| TLSH | `T14481C8D7AC01C3B146B18A4A5A7AD00CEB88203759B17461BC8CCC874F3C37EE3940EA` |
| SSDEEP | `48:NgEAW4xH87DWDawjYgYfTdv/dGhJjCO667kR5/Wo+yhg/3:FAW+87DGaeYzBndyJvR7k5/JZhg/3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_e61ada77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e61ada7705acfb837faa1fd96bc3f733ee174a3562e423ccd2707ddb15cccb8f"
    family = "unknown"
    file_name = "spxploy.vbs"
    file_type = "vbs"
    first_seen = "2026-08-19 19:13:45"
  condition:
    hash.sha256(0, filesize) == "e61ada7705acfb837faa1fd96bc3f733ee174a3562e423ccd2707ddb15cccb8f"
}
```

### Sample 74: `b0206e3effd34573`

| Field | Value |
|---|---|
| SHA-256 | `b0206e3effd345734a191751fd7dcf412e1264e5a9671347540183dc37507b4c` |
| Family label | `unknown` |
| File name | `sp.zip` |
| File type | `zip` |
| First seen | `2026-08-19 19:13:42` |
| Reporter | `juroots` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b6830a2ecc2e48c4d418573dbd69da0` |
| SHA-1 | `8fe04f97d7d9d1543ebab70d35985dc19a4d8df7` |
| SHA-256 | `b0206e3effd345734a191751fd7dcf412e1264e5a9671347540183dc37507b4c` |
| SHA3-384 | `6b53a5fbcc76c747a5b42deb14318bc0cf00379cf91f3a45127c6713feff06864bd8aa11c1eb6adccf0a50cf7da30d65` |
| TLSH | `T1B97733F1B442896BA9C1DCA0E7C5C184E28641E5CE743D77E16A53F3C2E7AC794E72A0` |
| SSDEEP | `786432:A87VCxbdhnfCJMGPk1Di4DNOCFzzt7P18AnX07UL3Ear:XQxbXnfCJMAYDi4D0C5Z9nT3Dr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_b0206e3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0206e3effd345734a191751fd7dcf412e1264e5a9671347540183dc37507b4c"
    family = "unknown"
    file_name = "sp.zip"
    file_type = "zip"
    first_seen = "2026-08-19 19:13:42"
  condition:
    hash.sha256(0, filesize) == "b0206e3effd345734a191751fd7dcf412e1264e5a9671347540183dc37507b4c"
}
```

### Sample 75: `1bc067d7bc73a520`

| Field | Value |
|---|---|
| SHA-256 | `1bc067d7bc73a5205544164b122634bf25d98c2b6e81a3353b895aa9d0d3707c` |
| Family label | `unknown` |
| File name | `s.bat` |
| File type | `bat` |
| First seen | `2026-08-19 19:13:23` |
| Reporter | `juroots` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ee2edd53545f4b8d24d5e0db2ce9ad3` |
| SHA-1 | `c7d4ffcefdb9920170bade35554df86e55c9fd3c` |
| SHA-256 | `1bc067d7bc73a5205544164b122634bf25d98c2b6e81a3353b895aa9d0d3707c` |
| SHA3-384 | `6a29e657b0cc502c6b5bca693a837f9eafe99d9785415b0c84d8cd53fe5c4c287d8c32eed899b0b67fb1f99230e86b47` |
| TLSH | `T19DC1525DF888267485F7962864E75305FDA7020F8128072079ED81E11FB275AE73DEEB` |
| SSDEEP | `96:1ZSeF8nWaoLJI3viVHEdsj/melJqpDi9kmCcLwFGBy2GJmCucmfmnlBmC2mVmomy:zRnMEHEdsrm+kmzL01Jm/cmfmnlBmjmP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_1bc067d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bc067d7bc73a5205544164b122634bf25d98c2b6e81a3353b895aa9d0d3707c"
    family = "unknown"
    file_name = "s.bat"
    file_type = "bat"
    first_seen = "2026-08-19 19:13:23"
  condition:
    hash.sha256(0, filesize) == "1bc067d7bc73a5205544164b122634bf25d98c2b6e81a3353b895aa9d0d3707c"
}
```

### Sample 76: `4f92f1b658856b26`

| Field | Value |
|---|---|
| SHA-256 | `4f92f1b658856b2662100c26dcd5f81525a74482b4fdebb16923ec27234f0a7e` |
| Family label | `RemusStealer` |
| File name | `r843.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:13:21` |
| Reporter | `juroots` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `656520f8a060f84253be72512beb3406` |
| SHA-1 | `4f3025e6b0053f462021519805a49eba5c019c91` |
| SHA-256 | `4f92f1b658856b2662100c26dcd5f81525a74482b4fdebb16923ec27234f0a7e` |
| SHA3-384 | `a32369cb3524547826006e9ed128ce88e051ce441ffd0812e9c5bff23f876c1e4b06fe9cfa100fd08bef1c83bdfd5efc` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T10E54CF05F7AA50ECE1778474C9554A62FB763E5643809B2F0360C772BF136A0BE29F61` |
| SSDEEP | `6144:jknVrlmji8AypzUBAzL2oWAEqekzOqS0XmTUmpwnpD59+5NYAW:WVrlmjivy9VzRWAjaqhXmrINU5NYv` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_076_4f92f1b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f92f1b658856b2662100c26dcd5f81525a74482b4fdebb16923ec27234f0a7e"
    family = "RemusStealer"
    file_name = "r843.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:13:21"
  condition:
    hash.sha256(0, filesize) == "4f92f1b658856b2662100c26dcd5f81525a74482b4fdebb16923ec27234f0a7e"
}
```

### Sample 77: `cd2cbf3277a26310`

| Field | Value |
|---|---|
| SHA-256 | `cd2cbf3277a263102361c9ee187e542c15ee02bc257dc17cd207f355f1d0f959` |
| Family label | `unknown` |
| File name | `ohijfalqvzldlhaqw.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:13:18` |
| Reporter | `juroots` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b3251f1572225a81019b2ac94834e0a` |
| SHA-1 | `b75637f8e0d50490e902cf9b076c17dfcbee882d` |
| SHA-256 | `cd2cbf3277a263102361c9ee187e542c15ee02bc257dc17cd207f355f1d0f959` |
| SHA3-384 | `976c94a1ffc67cd19b75abe4f2ad1e92253014d180aae89c610f706a348f4b1bad9c003e5b1b6838b7ba6ab4577611cf` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1EDB6233BF18B653EE06D1A3A3A77E150993BBA6165124C1296FCF48CCF250701E3E697` |
| SSDEEP | `196608:c2igH4kiY48zSXR2iAMT9nfE8G9R4YaHF39mjPfsOIBSAl:c2UkiY4Kmw1YWN4LawOI7l` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_cd2cbf32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd2cbf3277a263102361c9ee187e542c15ee02bc257dc17cd207f355f1d0f959"
    family = "unknown"
    file_name = "ohijfalqvzldlhaqw.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:13:18"
  condition:
    hash.sha256(0, filesize) == "cd2cbf3277a263102361c9ee187e542c15ee02bc257dc17cd207f355f1d0f959"
}
```

### Sample 78: `6f6cb5d3dbb2c6df`

| Field | Value |
|---|---|
| SHA-256 | `6f6cb5d3dbb2c6df2cedb919626fc5f273aba90eda86c9efd17d9af3855de79b` |
| Family label | `unknown` |
| File name | `niceworking.vbe` |
| File type | `vbe` |
| First seen | `2026-08-19 19:13:13` |
| Reporter | `juroots` |
| Tags | `vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `118e6db33ae48e0584143bfa2625c789` |
| SHA-1 | `379a4de374296ac9f23ed6212eda7a4aeafb2637` |
| SHA-256 | `6f6cb5d3dbb2c6df2cedb919626fc5f273aba90eda86c9efd17d9af3855de79b` |
| SHA3-384 | `74192a8d8a6bda5578ce7422910ce95f6661b0db575754bc74f6f9f307c2f608725964be09d33941646120b52217e596` |
| TLSH | `T1E053D2741B2848D3094BFC48E08217D6CFF8D21726AF2DB69340A696079D5DB9CB1DEB` |
| SSDEEP | `768:B7nElY1oE7gtfscWIXF2ObQKifq7+aD3QYAT4Lib22iSv5B5l3jkGt2c+DQihCX9:Ks/cdPpNstiJ2KmT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_6f6cb5d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f6cb5d3dbb2c6df2cedb919626fc5f273aba90eda86c9efd17d9af3855de79b"
    family = "unknown"
    file_name = "niceworking.vbe"
    file_type = "vbe"
    first_seen = "2026-08-19 19:13:13"
  condition:
    hash.sha256(0, filesize) == "6f6cb5d3dbb2c6df2cedb919626fc5f273aba90eda86c9efd17d9af3855de79b"
}
```

### Sample 79: `3c6ee1def9b061e4`

| Field | Value |
|---|---|
| SHA-256 | `3c6ee1def9b061e4591fd063ab29ea0df40e205a9c7540e23716f32313568f32` |
| Family label | `MeshAgent` |
| File name | `meshagents` |
| File type | `exe` |
| First seen | `2026-08-19 19:13:10` |
| Reporter | `juroots` |
| Tags | `exe, MeshAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20144aadc5ecd13c0658feca465d6cec` |
| SHA-1 | `a2d13717556393eb0605e15906c950a4eac35de7` |
| SHA-256 | `3c6ee1def9b061e4591fd063ab29ea0df40e205a9c7540e23716f32313568f32` |
| SHA3-384 | `00a6a8fda392d28c73242a02a67a55fa1ed01d69bc19b13e9dd63f500e813c7ac57c5323b892dee720c536bfca2aad9d` |
| IMPHASH | `ab2b59cb3676892d4f66e42ddba27623` |
| TLSH | `T177F58CD2A7A600E8E877F23CC5568117E7F2B81717709BCB15A44A760F23AD12E3E716` |
| SSDEEP | `49152:lMr6FQ0RIVvlifZ4NfamIzMShTmhTHjxpPL33pJW9xgVuw3wyfZ78bn9A35TL:9RYYT8HVB3pmGw63hL` |
| ICON-DHASH | `989a92d8d8daf2c0` |

#### Technical Assessment

- The sample is tracked as `MeshAgent` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MeshAgent_079_3c6ee1de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c6ee1def9b061e4591fd063ab29ea0df40e205a9c7540e23716f32313568f32"
    family = "MeshAgent"
    file_name = "meshagents"
    file_type = "exe"
    first_seen = "2026-08-19 19:13:10"
  condition:
    hash.sha256(0, filesize) == "3c6ee1def9b061e4591fd063ab29ea0df40e205a9c7540e23716f32313568f32"
}
```

### Sample 80: `a367a461a57c1dd3`

| Field | Value |
|---|---|
| SHA-256 | `a367a461a57c1dd3f2ce3a975ea950d37023870cc9083a54d471ff3cc266b43b` |
| Family label | `unknown` |
| File name | `load.bat` |
| File type | `bat` |
| First seen | `2026-08-19 19:13:06` |
| Reporter | `juroots` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `811e69d5075ffe5ab50de2ba02fde698` |
| SHA-1 | `f30ab635e29a13bc6f872a8298fda828e8a94bb4` |
| SHA-256 | `a367a461a57c1dd3f2ce3a975ea950d37023870cc9083a54d471ff3cc266b43b` |
| SHA3-384 | `c25d562727d2dfe093b92dc8647137577813f6d4db464c864e764850fa1a1264ea1dd2b77e61517d4494290e2b8158a6` |
| TLSH | `T1E501D6D7001EE47FDF23CB25D70986C6F12BDA7088EE334A6272585B7801A0533D96CA` |
| SSDEEP | `24:3LD8Y+M4dzxkj9mS1ATxTS1AhxlS1AlxmAS1AHxm1azAV8APAj8AJ:3LDXwEmSiSCS+SFY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_a367a461
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a367a461a57c1dd3f2ce3a975ea950d37023870cc9083a54d471ff3cc266b43b"
    family = "unknown"
    file_name = "load.bat"
    file_type = "bat"
    first_seen = "2026-08-19 19:13:06"
  condition:
    hash.sha256(0, filesize) == "a367a461a57c1dd3f2ce3a975ea950d37023870cc9083a54d471ff3cc266b43b"
}
```

### Sample 81: `8c23cd316bef30fb`

| Field | Value |
|---|---|
| SHA-256 | `8c23cd316bef30fbed31b835fd17ab0b21f0bcee84d69efc0d984db87fb58418` |
| Family label | `unknown` |
| File name | `iwantsomethingbetterformegetbackgoodthings.vbe` |
| File type | `vbe` |
| First seen | `2026-08-19 19:13:02` |
| Reporter | `juroots` |
| Tags | `vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51a4355ef1e15852dbf73e99c18da9e4` |
| SHA-1 | `f3ad9597f2d8d2cb9b2c936250f90c2dfc33094f` |
| SHA-256 | `8c23cd316bef30fbed31b835fd17ab0b21f0bcee84d69efc0d984db87fb58418` |
| SHA3-384 | `215fd8d42615a997e871f75de8ecca1aa5add0febd91256d87ce535087fac769b6d5f72b2990ab39c1eb966d9e1c1fe3` |
| TLSH | `T10A43E4741B2848D30A4BBC44E08217D6CFF8D21722AB6DB69340B796079D5DB9CB1DEB` |
| SSDEEP | `768:ET6JsmnEk/Pgbh5NuUY2o3yUjd4fMQe0vGD11P6xpbK854nncXBkRCmuTLUdTyUz:YT1zLTfw75jT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_8c23cd31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c23cd316bef30fbed31b835fd17ab0b21f0bcee84d69efc0d984db87fb58418"
    family = "unknown"
    file_name = "iwantsomethingbetterformegetbackgoodthings.vbe"
    file_type = "vbe"
    first_seen = "2026-08-19 19:13:02"
  condition:
    hash.sha256(0, filesize) == "8c23cd316bef30fbed31b835fd17ab0b21f0bcee84d69efc0d984db87fb58418"
}
```

### Sample 82: `4d2842d0602fe804`

| Field | Value |
|---|---|
| SHA-256 | `4d2842d0602fe8045297818515821c6646cc01d3bf3e684a5a888e7b25663965` |
| Family label | `unknown` |
| File name | `img_203145.png` |
| File type | `unknown` |
| First seen | `2026-08-19 19:12:59` |
| Reporter | `juroots` |
| Tags | `png` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ec45c67fec72613d3b553cddc25c2b8` |
| SHA-256 | `4d2842d0602fe8045297818515821c6646cc01d3bf3e684a5a888e7b25663965` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_4d2842d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d2842d0602fe8045297818515821c6646cc01d3bf3e684a5a888e7b25663965"
    family = "unknown"
    file_name = "img_203145.png"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:59"
  condition:
    hash.sha256(0, filesize) == "4d2842d0602fe8045297818515821c6646cc01d3bf3e684a5a888e7b25663965"
}
```

### Sample 83: `0bbc781ab36954da`

| Field | Value |
|---|---|
| SHA-256 | `0bbc781ab36954da7bd6108a3cd59fd5b1d0b18992e1f7de9abc147e30c83d80` |
| Family label | `RemcosRAT` |
| File name | `goodthingsarebestformehappeninggood.vbe` |
| File type | `vbe` |
| First seen | `2026-08-19 19:12:48` |
| Reporter | `juroots` |
| Tags | `RemcosRAT, vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c0b585b404139a0267b1f80879cc879` |
| SHA-1 | `17995df05c8b1fa6701916ad1ab7420296f41852` |
| SHA-256 | `0bbc781ab36954da7bd6108a3cd59fd5b1d0b18992e1f7de9abc147e30c83d80` |
| SHA3-384 | `ef1a56cbf73cbdd642cd87c14f974bfd3e361fd799eafad084d3a4eb5d69f8c34c3bab9c54d1b9ec5e3e713fe6c42c24` |
| TLSH | `T174439978150548D78113BD01E9831A96CFE8D21366EB1EB8C341A6CA079E7D7CCB6DEB` |
| SSDEEP | `768:FxAauLOzR6kTAplaGlMDD5X7i3h/io/me9UgJLYjp400Q:XuLOF7TATDlMDpi1u0Q` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_083_0bbc781a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bbc781ab36954da7bd6108a3cd59fd5b1d0b18992e1f7de9abc147e30c83d80"
    family = "RemcosRAT"
    file_name = "goodthingsarebestformehappeninggood.vbe"
    file_type = "vbe"
    first_seen = "2026-08-19 19:12:48"
  condition:
    hash.sha256(0, filesize) == "0bbc781ab36954da7bd6108a3cd59fd5b1d0b18992e1f7de9abc147e30c83d80"
}
```

### Sample 84: `5963a9491c91eae4`

| Field | Value |
|---|---|
| SHA-256 | `5963a9491c91eae44384e239284fdc74dc3db9ee1b13c24eccc516ece350df34` |
| Family label | `unknown` |
| File name | `goodcommuncaitionskilldevleipedfromthegood.js` |
| File type | `js` |
| First seen | `2026-08-19 19:12:44` |
| Reporter | `juroots` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19ae771572b0f04cc31deca91836ed97` |
| SHA-1 | `86ccea739cffd101aaccb08a45f3250e1cfbb099` |
| SHA-256 | `5963a9491c91eae44384e239284fdc74dc3db9ee1b13c24eccc516ece350df34` |
| SHA3-384 | `f4f839d89d75e547777e2a56faa14c34da607bccb17720bca634c679b6bdbbfaf998d5db6a5268319e31546bf35cc82f` |
| TLSH | `T1F1567D8E4155C9DD71EC9F19CC66F6D20B5E81270CA0BF133E2D655D9E48E0A332CAEA` |
| SSDEEP | `98304:ZAqv8h5g+Hj2xjMTadfxCCdlTrgYEXoh/hihzZqjRgyJJZ9HEXKZDsKsmTZ/raDF:ZZ7+CSTIpzdNr0z8RxTZ9dZI0Zqh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_5963a949
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5963a9491c91eae44384e239284fdc74dc3db9ee1b13c24eccc516ece350df34"
    family = "unknown"
    file_name = "goodcommuncaitionskilldevleipedfromthegood.js"
    file_type = "js"
    first_seen = "2026-08-19 19:12:44"
  condition:
    hash.sha256(0, filesize) == "5963a9491c91eae44384e239284fdc74dc3db9ee1b13c24eccc516ece350df34"
}
```

### Sample 85: `60f3280493c50acf`

| Field | Value |
|---|---|
| SHA-256 | `60f3280493c50acf8ccc3b128177e714a7dd58dc5f89871ad6683ab1539b382c` |
| Family label | `unknown` |
| File name | `go_b3.bat` |
| File type | `bat` |
| First seen | `2026-08-19 19:12:40` |
| Reporter | `juroots` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e74801a02e6ff13c0a94c5b274b78569` |
| SHA-1 | `134ee746bcc9bf98a51f08e8dd4b6d53f4369213` |
| SHA-256 | `60f3280493c50acf8ccc3b128177e714a7dd58dc5f89871ad6683ab1539b382c` |
| SHA3-384 | `3d519dfc2de7db510f4a28b1cc32f9d0c51f366b7107d1d41b6357cf010aafdeefe17c9b7afa2b12adf2062483938077` |
| TLSH | `T18421E095A464507386ED0ED12E07AD24330F94F21E88D7CB7476497DA826A6AE2793C2` |
| SSDEEP | `24:AcuVrY1uNQ5iZpyZwMvXA051A4HVpG3BkCFuVM5GOD8A4no0k8vC7zPxjuD5lnA5:zuyaIssXlTH+kauXBvktzPKI00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_60f32804
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60f3280493c50acf8ccc3b128177e714a7dd58dc5f89871ad6683ab1539b382c"
    family = "unknown"
    file_name = "go_b3.bat"
    file_type = "bat"
    first_seen = "2026-08-19 19:12:40"
  condition:
    hash.sha256(0, filesize) == "60f3280493c50acf8ccc3b128177e714a7dd58dc5f89871ad6683ab1539b382c"
}
```

### Sample 86: `cc2b96a6c3555189`

| Field | Value |
|---|---|
| SHA-256 | `cc2b96a6c355518992425086221902594f98c16b2825f517d961f35368bba14d` |
| Family label | `unknown` |
| File name | `crypted.ps1.5` |
| File type | `unknown` |
| First seen | `2026-08-19 19:12:36` |
| Reporter | `juroots` |
| Tags | `5` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d525d94089544aad1276602cb9551c12` |
| SHA-256 | `cc2b96a6c355518992425086221902594f98c16b2825f517d961f35368bba14d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_cc2b96a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc2b96a6c355518992425086221902594f98c16b2825f517d961f35368bba14d"
    family = "unknown"
    file_name = "crypted.ps1.5"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:36"
  condition:
    hash.sha256(0, filesize) == "cc2b96a6c355518992425086221902594f98c16b2825f517d961f35368bba14d"
}
```

### Sample 87: `d1aaf73552c77ab6`

| Field | Value |
|---|---|
| SHA-256 | `d1aaf73552c77ab6bea5c26e39e7d2d303b395314c3abe7fd426de90463c835d` |
| Family label | `unknown` |
| File name | `crypted.ps1.4` |
| File type | `unknown` |
| First seen | `2026-08-19 19:12:33` |
| Reporter | `juroots` |
| Tags | `4` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a54103514ab8cd9142c2af577bbc55c4` |
| SHA-256 | `d1aaf73552c77ab6bea5c26e39e7d2d303b395314c3abe7fd426de90463c835d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_d1aaf735
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1aaf73552c77ab6bea5c26e39e7d2d303b395314c3abe7fd426de90463c835d"
    family = "unknown"
    file_name = "crypted.ps1.4"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:33"
  condition:
    hash.sha256(0, filesize) == "d1aaf73552c77ab6bea5c26e39e7d2d303b395314c3abe7fd426de90463c835d"
}
```

### Sample 88: `f0262f2f37f5557c`

| Field | Value |
|---|---|
| SHA-256 | `f0262f2f37f5557cca06d49b951ab28c49e5796fba28365a117abaed031aa53a` |
| Family label | `unknown` |
| File name | `crypted.ps1.3` |
| File type | `unknown` |
| First seen | `2026-08-19 19:12:28` |
| Reporter | `juroots` |
| Tags | `3` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fe3c0b3a0cdecf91b9ff46b16faf2b8` |
| SHA-256 | `f0262f2f37f5557cca06d49b951ab28c49e5796fba28365a117abaed031aa53a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_f0262f2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0262f2f37f5557cca06d49b951ab28c49e5796fba28365a117abaed031aa53a"
    family = "unknown"
    file_name = "crypted.ps1.3"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:28"
  condition:
    hash.sha256(0, filesize) == "f0262f2f37f5557cca06d49b951ab28c49e5796fba28365a117abaed031aa53a"
}
```

### Sample 89: `adfefc2614695191`

| Field | Value |
|---|---|
| SHA-256 | `adfefc2614695191b1a6e4050e53784a56204f03da3f1a6c55a90ae08ed16e72` |
| Family label | `unknown` |
| File name | `crypted.ps1.2` |
| File type | `unknown` |
| First seen | `2026-08-19 19:12:24` |
| Reporter | `juroots` |
| Tags | `2` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42a5b4406142d9f5833653f7b6e7a487` |
| SHA-256 | `adfefc2614695191b1a6e4050e53784a56204f03da3f1a6c55a90ae08ed16e72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_adfefc26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adfefc2614695191b1a6e4050e53784a56204f03da3f1a6c55a90ae08ed16e72"
    family = "unknown"
    file_name = "crypted.ps1.2"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:24"
  condition:
    hash.sha256(0, filesize) == "adfefc2614695191b1a6e4050e53784a56204f03da3f1a6c55a90ae08ed16e72"
}
```

### Sample 90: `4d70fd13a1aa624a`

| Field | Value |
|---|---|
| SHA-256 | `4d70fd13a1aa624abe0b5941dd3130f28e357daa644811550716197491a897c4` |
| Family label | `unknown` |
| File name | `crypted.ps1.1` |
| File type | `unknown` |
| First seen | `2026-08-19 19:12:20` |
| Reporter | `juroots` |
| Tags | `1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8e977a4bf5eb5f2a30ab322b355b04f` |
| SHA-256 | `4d70fd13a1aa624abe0b5941dd3130f28e357daa644811550716197491a897c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_4d70fd13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d70fd13a1aa624abe0b5941dd3130f28e357daa644811550716197491a897c4"
    family = "unknown"
    file_name = "crypted.ps1.1"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:20"
  condition:
    hash.sha256(0, filesize) == "4d70fd13a1aa624abe0b5941dd3130f28e357daa644811550716197491a897c4"
}
```

### Sample 91: `802069736d28e5c1`

| Field | Value |
|---|---|
| SHA-256 | `802069736d28e5c16bce132a1cfe905f6f9c7ae44500cb32c3a34e93452400d6` |
| Family label | `unknown` |
| File name | `battlebot.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:12:12` |
| Reporter | `juroots` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ae8142ae790ed498c04b85f489fde96` |
| SHA-1 | `18fff703be24dc90bd82b4e4e63f757ab919c4e8` |
| SHA-256 | `802069736d28e5c16bce132a1cfe905f6f9c7ae44500cb32c3a34e93452400d6` |
| SHA3-384 | `735552fc7d26704208d2e543080eacae9e98bd3796a268995270831ad2a67c1002871704fae079511a0fb19f2a63a4ef` |
| IMPHASH | `3a2ffbe33592310cb39abe8a3f252614` |
| TLSH | `T1C9258D33E213C866E9A764344C0B55B48830FF52A97AA97E3BE87D1CDF326D37825152` |
| SSDEEP | `12288:w7Psf46qDSsacPAwEAcXGBng9hSQq5yqeUF0xp58jtsz6SMz:wDi468PPAg0Gm90bUUaF66VMz` |
| ICON-DHASH | `399998ecd4d46c0e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_80206973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "802069736d28e5c16bce132a1cfe905f6f9c7ae44500cb32c3a34e93452400d6"
    family = "unknown"
    file_name = "battlebot.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:12:12"
  condition:
    hash.sha256(0, filesize) == "802069736d28e5c16bce132a1cfe905f6f9c7ae44500cb32c3a34e93452400d6"
}
```

### Sample 92: `98fd04031af897a6`

| Field | Value |
|---|---|
| SHA-256 | `98fd04031af897a657b71eebc1a3d6576f78d52a497c11868fbbce1dda893fbf` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.msi` |
| File type | `msi` |
| First seen | `2026-08-19 19:12:07` |
| Reporter | `juroots` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0675f7ed8665b16d101ed18748c84206` |
| SHA-1 | `061d976a62253a44067781a96f0446fb10455c53` |
| SHA-256 | `98fd04031af897a657b71eebc1a3d6576f78d52a497c11868fbbce1dda893fbf` |
| SHA3-384 | `53d78de8fa010911263443425164948b1f43ee9b786fb05272e961c577d1c09af844ace217cc4a51c8ce655ce63bf414` |
| TLSH | `T156A6232063E58466F1B70A3EEE3586F4597A7E25DE12C08F63A4791C6D32E50CA72373` |
| SSDEEP | `196608:AgHxiFSsYwwSA/OdB+i4xzeebgHxiFSsYwwSA/OdB+EgHxiFSsYwwSA/OdB+LgHJ:A2xiFxbwpacC22xiFxbwpaD2xiFxbwpp` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_092_98fd0403
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98fd04031af897a657b71eebc1a3d6576f78d52a497c11868fbbce1dda893fbf"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-08-19 19:12:07"
  condition:
    hash.sha256(0, filesize) == "98fd04031af897a657b71eebc1a3d6576f78d52a497c11868fbbce1dda893fbf"
}
```

### Sample 93: `2671b93e5dccb24c`

| Field | Value |
|---|---|
| SHA-256 | `2671b93e5dccb24ce9d3461a6f392f1251e78d3e11b6268475a51bed4298dffd` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:12:03` |
| Reporter | `juroots` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b64b26902de06f3fbe83ec176b77abd7` |
| SHA-1 | `c42d4f45aaa98e44e77e4687c887022f7a8878c4` |
| SHA-256 | `2671b93e5dccb24ce9d3461a6f392f1251e78d3e11b6268475a51bed4298dffd` |
| SHA3-384 | `3fd1f673c68a66d5f20ee6ef7cc7dffc2cc9796bccfd3188ce01cae3b3e2fe7e443715e175d2e9ac55bce3a225fcbbe4` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T158D61200B3D995B5D1BF0A38E87D82696635BC044716C6BF5394BA693E32BC09E32773` |
| SSDEEP | `196608:wfefPnqXtv0AbJZPXtv0A4Xtv0APXtv0A4Xtv0AB:atRZvt6tjtSt1` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_093_2671b93e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2671b93e5dccb24ce9d3461a6f392f1251e78d3e11b6268475a51bed4298dffd"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:12:03"
  condition:
    hash.sha256(0, filesize) == "2671b93e5dccb24ce9d3461a6f392f1251e78d3e11b6268475a51bed4298dffd"
}
```

### Sample 94: `f94db5a93b19e180`

| Field | Value |
|---|---|
| SHA-256 | `f94db5a93b19e1800be99cb0be2fb21794d3c89ccb588b53739a62c587bc20e6` |
| Family label | `unknown` |
| File name | `OCUDLOMO.msi` |
| File type | `msi` |
| First seen | `2026-08-19 19:11:58` |
| Reporter | `juroots` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f16803d0f0e9cbf0f154c2d43a39c353` |
| SHA-1 | `8077bd87310683ca1f4ded78bf350752eaf6423a` |
| SHA-256 | `f94db5a93b19e1800be99cb0be2fb21794d3c89ccb588b53739a62c587bc20e6` |
| SHA3-384 | `8eb4d68933de87cdc56bdd15238d45e5d2eb1131d6d343c876c3bbb665ad7384b77e0977a9226c463b0d73aa9c87cab4` |
| TLSH | `T1D1C63303F8B2DB04F6AE257DD590C65269D4CE5E7EA2284B3B5C30E5E6B32F421C6B05` |
| SSDEEP | `196608:Nsr37LikhFkfbcu8DnFpJG00aH0u4KWXmwlRr+2axNsnqZ:NyLmHou8DnFpbF0u4KwplRrQu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_f94db5a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94db5a93b19e1800be99cb0be2fb21794d3c89ccb588b53739a62c587bc20e6"
    family = "unknown"
    file_name = "OCUDLOMO.msi"
    file_type = "msi"
    first_seen = "2026-08-19 19:11:58"
  condition:
    hash.sha256(0, filesize) == "f94db5a93b19e1800be99cb0be2fb21794d3c89ccb588b53739a62c587bc20e6"
}
```

### Sample 95: `417f396852e6b1f4`

| Field | Value |
|---|---|
| SHA-256 | `417f396852e6b1f4360ff1e4c16b85bd65ba46faa5c71fb97816b0a796d8055d` |
| Family label | `unknown` |
| File name | `Loader.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:11:54` |
| Reporter | `juroots` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a60a2c8a9473d7b087e7e3e19044b7fd` |
| SHA-1 | `21c7f3693b148254d4d9703204534857b25fc03f` |
| SHA-256 | `417f396852e6b1f4360ff1e4c16b85bd65ba46faa5c71fb97816b0a796d8055d` |
| SHA3-384 | `9817e4541a4d776aa854035183b2025b1061daa977fe1f15123cb844c1afc0918201813e675324cbb68ef21a79720efb` |
| IMPHASH | `4e47736629dc02327ea34cef775732eb` |
| TLSH | `T10EF502BD62503398D01E88385437FD55B1F6556E0EB986E976DBBAC03B7E810E702B0B` |
| SSDEEP | `49152:sP2SGzIaaxhu1ngj82MractKOGOU1gPQKu9uFgyrAqto3BNDU+bzhcEibAwy0ZBL:g0IhutgAraqNUiLu9uFHrA7NDJQf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_417f3968
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "417f396852e6b1f4360ff1e4c16b85bd65ba46faa5c71fb97816b0a796d8055d"
    family = "unknown"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:11:54"
  condition:
    hash.sha256(0, filesize) == "417f396852e6b1f4360ff1e4c16b85bd65ba46faa5c71fb97816b0a796d8055d"
}
```

### Sample 96: `80719d8ef5d25eda`

| Field | Value |
|---|---|
| SHA-256 | `80719d8ef5d25edada79486feff7f73f914409c24faf0979ab805010c0140663` |
| Family label | `unknown` |
| File name | `Bembemi.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:11:50` |
| Reporter | `juroots` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8aba7a01bfc82fa24f2eb50aaa3e684` |
| SHA-1 | `99f457dd33e582aac4a6be53023e98c42d63e810` |
| SHA-256 | `80719d8ef5d25edada79486feff7f73f914409c24faf0979ab805010c0140663` |
| SHA3-384 | `461292b40b053f77399970e6304d64e14ec6fe0682728b60dd3139aed1dd22a9a552ffd6d50912c4067a7b50182488c6` |
| IMPHASH | `254bc68f13467887f90e72a94dbc6b01` |
| TLSH | `T176288D43B2A60094E17BD1788A577513EB71BC1943F0A6DB7294EA242F73BE06B7E740` |
| SSDEEP | `786432:5TKOpahgjHu99FLJMCHyb4Gzb1cEkDSskHsEYgOQ4PMKB9MuUjBySt1U:pNMtnBccSt` |
| ICON-DHASH | `737363389c2c586b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_80719d8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80719d8ef5d25edada79486feff7f73f914409c24faf0979ab805010c0140663"
    family = "unknown"
    file_name = "Bembemi.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:11:50"
  condition:
    hash.sha256(0, filesize) == "80719d8ef5d25edada79486feff7f73f914409c24faf0979ab805010c0140663"
}
```

### Sample 97: `0ee2eb5659a3fe9f`

| Field | Value |
|---|---|
| SHA-256 | `0ee2eb5659a3fe9ff41b0b80d8dc0f5f85b2127111f60860d024f74d9719ca77` |
| Family label | `unknown` |
| File name | `Av.scr` |
| File type | `pdf` |
| First seen | `2026-08-19 19:11:34` |
| Reporter | `juroots` |
| Tags | `pdf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `327e96e50818798502706d6a87148003` |
| SHA-1 | `6c492c1791891046b4cced1480eb3d6e4e0d0d0f` |
| SHA-256 | `0ee2eb5659a3fe9ff41b0b80d8dc0f5f85b2127111f60860d024f74d9719ca77` |
| SHA3-384 | `9281ae48b192ae3ecd4ae80f17a2aed8c2f71c72e14ab39b16b14a12d0c508a6182b2040786bb6146f0dfc7973da59a7` |
| TLSH | `T19B150169EA3BD8A8CA420430ED5C67D2DAF9C0E24D5424736CA88E862D4DD19FC745FB` |
| SSDEEP | `12288:esRac0NsCG21D855OGPjimJGKtoRuyXa3dgaF6Jtag/GhzOjr4gbj7VzoVleMAXA:nkcpyo55EGoR9Xa3yaOtPuNVgb9iFWa1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `pdf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_0ee2eb56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ee2eb5659a3fe9ff41b0b80d8dc0f5f85b2127111f60860d024f74d9719ca77"
    family = "unknown"
    file_name = "Av.scr"
    file_type = "pdf"
    first_seen = "2026-08-19 19:11:34"
  condition:
    hash.sha256(0, filesize) == "0ee2eb5659a3fe9ff41b0b80d8dc0f5f85b2127111f60860d024f74d9719ca77"
}
```

### Sample 98: `aaeae4c452096b11`

| Field | Value |
|---|---|
| SHA-256 | `aaeae4c452096b11902e0077e6fab22aa3d1f50266edb2643e38278e0f5c6c0c` |
| Family label | `unknown` |
| File name | `BAC_PC壳.exe` |
| File type | `exe` |
| First seen | `2026-08-19 19:11:22` |
| Reporter | `juroots` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0efac239d6ff7e1067eae2027509dfe8` |
| SHA-1 | `0c95a1651470f4d5624390feb494fc2f5e264457` |
| SHA-256 | `aaeae4c452096b11902e0077e6fab22aa3d1f50266edb2643e38278e0f5c6c0c` |
| SHA3-384 | `d0645d4a5d2ba4aa0639288cc31f79ed6131f3f0e3dde52c6bf996b92dcbe44062804fb1ac8e2e8998f2ac745141796f` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1FCC633AAB75A08DCE84F233B98D289679BF178214BE482C757F85A040E635D4FF39741` |
| SSDEEP | `196608:soV7MF00W8/LayNTwhL1FUV55AH8DWu0krdpWrGCO+tbEOQH2dOJ2/lVJIJ7Lk0G:spxW8yL1FUT5AHA5TWru+tbPQHdJ2/lh` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_aaeae4c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaeae4c452096b11902e0077e6fab22aa3d1f50266edb2643e38278e0f5c6c0c"
    family = "unknown"
    file_name = "BAC_PC壳.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:11:22"
  condition:
    hash.sha256(0, filesize) == "aaeae4c452096b11902e0077e6fab22aa3d1f50266edb2643e38278e0f5c6c0c"
}
```

### Sample 99: `9629db9638a81455`

| Field | Value |
|---|---|
| SHA-256 | `9629db9638a8145583ceb452d0328fe88af94fded7c1f228c8adf4240399c15d` |
| Family label | `Mirai` |
| File name | `ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19.elf` |
| File type | `elf` |
| First seen | `2026-08-19 18:56:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b00f7f605f799d56b6c743d6ef8d9ec9` |
| SHA-1 | `b523472bc02d8d3fd1dd291a88eed151bbba2f12` |
| SHA-256 | `9629db9638a8145583ceb452d0328fe88af94fded7c1f228c8adf4240399c15d` |
| SHA3-384 | `e6a1c97484a8e134e4533cb20138380f44d32714bae29f4ec20001d410da884f00ea583d0a7532a93302ef35deeeeb87` |
| TLSH | `T18E449D01FB180A23C1931DB40E7F07A7D369899228F9F11E6A0E7F5647316BB96877D8` |
| SSDEEP | `6144:QXFYhqm7BkuxGHY0XOGQr7tT4dxAw++VL5LLHhTb7CF:6wqmGuqHQrBJ+i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_9629db96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9629db9638a8145583ceb452d0328fe88af94fded7c1f228c8adf4240399c15d"
    family = "Mirai"
    file_name = "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19.elf"
    file_type = "elf"
    first_seen = "2026-08-19 18:56:46"
  condition:
    hash.sha256(0, filesize) == "9629db9638a8145583ceb452d0328fe88af94fded7c1f228c8adf4240399c15d"
}
```

### Sample 100: `ad3978ae70de2c57`

| Field | Value |
|---|---|
| SHA-256 | `ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19` |
| Family label | `Mirai` |
| File name | `ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19.elf` |
| File type | `elf` |
| First seen | `2026-08-19 18:55:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `896ff65fac9bbb5ce1a2e640b69f5c86` |
| SHA-1 | `8c0a13d8e2f16d0459d63da71ae9220a3c32e098` |
| SHA-256 | `ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19` |
| SHA3-384 | `4122a9122087511bace33e1a7d8daabc4c1aa254ec6c742932c949ac7ad9a77762d9f49b86df9a1a2cce18e76d59d0e5` |
| TLSH | `T12EA3121D510DCC47FEF716792AA490D4AB28DBA83EC29EB11710CBAD942373F854497B` |
| SSDEEP | `3072:ipvtpsTZdB0uGyLjFEt7Wx0ScpRLDXS4u+qgwy:i/UrGyLJEATcp5DX3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_ad3978ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19"
    family = "Mirai"
    file_name = "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19.elf"
    file_type = "elf"
    first_seen = "2026-08-19 18:55:46"
  condition:
    hash.sha256(0, filesize) == "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19"
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
 * Generated: 2026-08-20T01:54:36.164481+00:00
 */

rule MalwareBazaar_ValleyRAT_001_9df49e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9df49e9a905999b066c1994261c2aefa40bbfe54ff978ea75c131dc7e1a573b9"
    family = "ValleyRAT"
    file_name = "8E2FF0A0925C9D4FDBCC3DCACAF7C9B6.dll"
    file_type = "dll"
    first_seen = "2026-08-20 01:50:15"
  condition:
    hash.sha256(0, filesize) == "9df49e9a905999b066c1994261c2aefa40bbfe54ff978ea75c131dc7e1a573b9"
}

rule MalwareBazaar_unknown_002_c634f207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c634f2071b0725a0d2c29852fb0b7bae3489ea724c1c3a0943ed71582a054c50"
    family = "unknown"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 01:31:40"
  condition:
    hash.sha256(0, filesize) == "c634f2071b0725a0d2c29852fb0b7bae3489ea724c1c3a0943ed71582a054c50"
}

rule MalwareBazaar_Mirai_003_c897c158
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c897c15850310c244a6d8f27a6c0387d6359b1326120c8eca9ee27d4c6a6ff3c"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-20 00:58:48"
  condition:
    hash.sha256(0, filesize) == "c897c15850310c244a6d8f27a6c0387d6359b1326120c8eca9ee27d4c6a6ff3c"
}

rule MalwareBazaar_Mirai_004_8bc94ede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bc94ede491e67b32af3789f9807b76bebe02f69bb9dbec17342c1e00bd6d7d3"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-20 00:58:47"
  condition:
    hash.sha256(0, filesize) == "8bc94ede491e67b32af3789f9807b76bebe02f69bb9dbec17342c1e00bd6d7d3"
}

rule MalwareBazaar_unknown_005_fd84e3dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd84e3dcb36b548098af61a9d3479ca0b8e2ab5e9e688bda32a0fb34d0e93806"
    family = "unknown"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-08-20 00:58:46"
  condition:
    hash.sha256(0, filesize) == "fd84e3dcb36b548098af61a9d3479ca0b8e2ab5e9e688bda32a0fb34d0e93806"
}

rule MalwareBazaar_Mirai_006_8182fb01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8182fb0126fe3f44eaf12f065a054a64ecfb73b884f68969ebbdc15cfeffba29"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:56"
  condition:
    hash.sha256(0, filesize) == "8182fb0126fe3f44eaf12f065a054a64ecfb73b884f68969ebbdc15cfeffba29"
}

rule MalwareBazaar_Mirai_007_57ba0c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57ba0c6c3195857e972d9764566e57db25a5e49de4efb8f7ffb545f74740b123"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:55"
  condition:
    hash.sha256(0, filesize) == "57ba0c6c3195857e972d9764566e57db25a5e49de4efb8f7ffb545f74740b123"
}

rule MalwareBazaar_Mirai_008_87d14d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87d14d2c5609cefb229cd3fff7a708e7bc357a92ae4348382e2bbdd3d3b7ae4c"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:54"
  condition:
    hash.sha256(0, filesize) == "87d14d2c5609cefb229cd3fff7a708e7bc357a92ae4348382e2bbdd3d3b7ae4c"
}

rule MalwareBazaar_unknown_009_e266c8d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e266c8d3b55220ad94d6c27da4758809bf0e8c359aeb63e6592a6de52a216c95"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-08-20 00:55:52"
  condition:
    hash.sha256(0, filesize) == "e266c8d3b55220ad94d6c27da4758809bf0e8c359aeb63e6592a6de52a216c95"
}

rule MalwareBazaar_Mirai_010_a2a18c18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2a18c18182243ce6b54481ae362535871b4111a9204b39aab6fb8a46d93255d"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:51"
  condition:
    hash.sha256(0, filesize) == "a2a18c18182243ce6b54481ae362535871b4111a9204b39aab6fb8a46d93255d"
}

rule MalwareBazaar_Mirai_011_f8439179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8439179f9c964fbefb1ffef0a6749a772242fee4b9432976bf6b587b786a2c8"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:49"
  condition:
    hash.sha256(0, filesize) == "f8439179f9c964fbefb1ffef0a6749a772242fee4b9432976bf6b587b786a2c8"
}

rule MalwareBazaar_Mirai_012_3f205f60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f205f6073c62cd2e6f5499f07c0fb3ed269d3494a2bb8668d80fb3d95b28fc2"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:48"
  condition:
    hash.sha256(0, filesize) == "3f205f6073c62cd2e6f5499f07c0fb3ed269d3494a2bb8668d80fb3d95b28fc2"
}

rule MalwareBazaar_unknown_013_fe8815ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe8815cedb65e08a83ce35a86a3b26d7297134029b60f64dc210e51ad5d7845a"
    family = "unknown"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-20 00:55:47"
  condition:
    hash.sha256(0, filesize) == "fe8815cedb65e08a83ce35a86a3b26d7297134029b60f64dc210e51ad5d7845a"
}

rule MalwareBazaar_unknown_014_5be539b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1"
    family = "unknown"
    file_name = "5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1.bin"
    file_type = "exe"
    first_seen = "2026-08-20 00:11:35"
  condition:
    hash.sha256(0, filesize) == "5be539b6e019787af5f8345f005086609cacf27ed943881c53f4191ea149e5e1"
}

rule MalwareBazaar_unknown_015_1b7d9706
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872"
    family = "unknown"
    file_name = "1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 23:55:48"
  condition:
    hash.sha256(0, filesize) == "1b7d970654a2a88ebe3938b18d85fd494d19ec12f0c5568e655c2608eecf3872"
}

rule MalwareBazaar_WannaCry_016_809c23d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f"
    family = "WannaCry"
    file_name = "809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f"
    file_type = "exe"
    first_seen = "2026-08-19 23:48:09"
  condition:
    hash.sha256(0, filesize) == "809c23d1a24c9ee596c8aae7645d4939645128a48343609817bbbcca245ebc9f"
}

rule MalwareBazaar_unknown_017_1f12614a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e"
    family = "unknown"
    file_name = "1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e.bin"
    file_type = "zip"
    first_seen = "2026-08-19 23:45:52"
  condition:
    hash.sha256(0, filesize) == "1f12614ae3595a8cd6a4d3d5e444d244bde120c5f4457e1038342a41eafb299e"
}

rule MalwareBazaar_unknown_018_b3f2ff24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e"
    family = "unknown"
    file_name = "b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e.elf"
    file_type = "elf"
    first_seen = "2026-08-19 23:40:50"
  condition:
    hash.sha256(0, filesize) == "b3f2ff2437ceb642bafa11c804bf648ac9cb96abe85483ae7cb3e9fc9701796e"
}

rule MalwareBazaar_unknown_019_5d8bfb8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a"
    family = "unknown"
    file_name = "5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 23:27:00"
  condition:
    hash.sha256(0, filesize) == "5d8bfb8c4b67e28997bc9887f7ebf9491ea0a713f98bb0c8d016be658645968a"
}

rule MalwareBazaar_unknown_020_7da8c7aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c"
    family = "unknown"
    file_name = "7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 23:23:48"
  condition:
    hash.sha256(0, filesize) == "7da8c7aa6b48cb727d97f5a7843d41fce97e4bab56d74166b059d816f650f69c"
}

rule MalwareBazaar_unknown_021_7628144c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061"
    family = "unknown"
    file_name = "7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061.bin"
    file_type = "unknown"
    first_seen = "2026-08-19 22:50:54"
  condition:
    hash.sha256(0, filesize) == "7628144c2c2cb8413dba31e9581a7291b216b4352e6e9826b2e5ec730ab30061"
}

rule MalwareBazaar_DCRat_022_d86bf7e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86bf7e59e6320920f737526089e4dfac56bacf346ae60d6d6bce015b33953cb"
    family = "DCRat"
    file_name = "254559fa505cfe6b680dc477cfe11dba.exe"
    file_type = "exe"
    first_seen = "2026-08-19 22:50:10"
  condition:
    hash.sha256(0, filesize) == "d86bf7e59e6320920f737526089e4dfac56bacf346ae60d6d6bce015b33953cb"
}

rule MalwareBazaar_unknown_023_d3692f7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485"
    family = "unknown"
    file_name = "d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485.bin"
    file_type = "exe"
    first_seen = "2026-08-19 22:06:43"
  condition:
    hash.sha256(0, filesize) == "d3692f7f99d26b8ed39d82909f44c5ac4628fcc434ff13248fe6eac8e595b485"
}

rule MalwareBazaar_unknown_024_7743d51b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398"
    family = "unknown"
    file_name = "7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398"
    file_type = "unknown"
    first_seen = "2026-08-19 21:54:18"
  condition:
    hash.sha256(0, filesize) == "7743d51b055f27435d80785e6a677e4c596be622ccae6f6ebc182499e0a75398"
}

rule MalwareBazaar_unknown_025_32e9d752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32e9d75275d0daed938898678da75b29cca0c9601490ddccb27868837fbae967"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-19 21:35:52"
  condition:
    hash.sha256(0, filesize) == "32e9d75275d0daed938898678da75b29cca0c9601490ddccb27868837fbae967"
}

rule MalwareBazaar_unknown_026_f58f8c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f58f8c260181fd11f4326c978cc648e7b5085eed6ee513a6f4ddef1f4ef5b6bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 21:34:49"
  condition:
    hash.sha256(0, filesize) == "f58f8c260181fd11f4326c978cc648e7b5085eed6ee513a6f4ddef1f4ef5b6bf"
}

rule MalwareBazaar_unknown_027_4c5972e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c5972e2d15fb818e463644331724242526d5049ba19c37223e78b23613771a0"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-08-19 21:32:49"
  condition:
    hash.sha256(0, filesize) == "4c5972e2d15fb818e463644331724242526d5049ba19c37223e78b23613771a0"
}

rule MalwareBazaar_unknown_028_d60a5dd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d60a5dd9baf1be9ae780136c614bd4c51a26590fa327156d80763798a85f1741"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-19 21:09:03"
  condition:
    hash.sha256(0, filesize) == "d60a5dd9baf1be9ae780136c614bd4c51a26590fa327156d80763798a85f1741"
}

rule MalwareBazaar_Mirai_029_0ff85f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ff85f5f951339f6c7e77bfca8b4075722b76c1996ffbbf6c1819f813055e406"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-19 20:56:54"
  condition:
    hash.sha256(0, filesize) == "0ff85f5f951339f6c7e77bfca8b4075722b76c1996ffbbf6c1819f813055e406"
}

rule MalwareBazaar_unknown_030_9bf57603
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bf57603ac37a59e4477c517c9a7a799941e165d2f8ae9e587421b1550087457"
    family = "unknown"
    file_name = "chrome_sample.zip"
    file_type = "zip"
    first_seen = "2026-08-19 20:49:02"
  condition:
    hash.sha256(0, filesize) == "9bf57603ac37a59e4477c517c9a7a799941e165d2f8ae9e587421b1550087457"
}

rule MalwareBazaar_Mirai_031_367d7ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "367d7ffee0fb655dc63c7313ffc292b1dab6135dc41c133966a6e09d9d5e3c05"
    family = "Mirai"
    file_name = "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:46:43"
  condition:
    hash.sha256(0, filesize) == "367d7ffee0fb655dc63c7313ffc292b1dab6135dc41c133966a6e09d9d5e3c05"
}

rule MalwareBazaar_Mirai_032_1d841c5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d841c5b336df35e52bfec97e27a4472b53a7fd15ea9402d3fee4655a2cb8ee2"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-19 20:46:03"
  condition:
    hash.sha256(0, filesize) == "1d841c5b336df35e52bfec97e27a4472b53a7fd15ea9402d3fee4655a2cb8ee2"
}

rule MalwareBazaar_Mirai_033_2bff8567
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1"
    family = "Mirai"
    file_name = "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:45:48"
  condition:
    hash.sha256(0, filesize) == "2bff85672c484c31480aead0a341c1623a8872c84b72074999899d2bd073bfc1"
}

rule MalwareBazaar_Mirai_034_c43f736f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c43f736f1b26cf059bdb961766ddabdcc1ccde7be851b670a2f88bb67dee2dc3"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-19 20:44:53"
  condition:
    hash.sha256(0, filesize) == "c43f736f1b26cf059bdb961766ddabdcc1ccde7be851b670a2f88bb67dee2dc3"
}

rule MalwareBazaar_Mirai_035_f59794a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f59794a0fc981089ed7460eb5d9cb407ad89d0bc41375a6ce9854fe38781ba76"
    family = "Mirai"
    file_name = "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:45"
  condition:
    hash.sha256(0, filesize) == "f59794a0fc981089ed7460eb5d9cb407ad89d0bc41375a6ce9854fe38781ba76"
}

rule MalwareBazaar_Mirai_036_01bc7964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01bc79640c037a1f40086ed872caf75094ae53084dac5674b158179156c5eccd"
    family = "Mirai"
    file_name = "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:43"
  condition:
    hash.sha256(0, filesize) == "01bc79640c037a1f40086ed872caf75094ae53084dac5674b158179156c5eccd"
}

rule MalwareBazaar_Mirai_037_20eb4840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20eb4840ec929f6c8aedb2b9d74f3fce00ea789fbd8208651cba8282d67d9f33"
    family = "Mirai"
    file_name = "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:40"
  condition:
    hash.sha256(0, filesize) == "20eb4840ec929f6c8aedb2b9d74f3fce00ea789fbd8208651cba8282d67d9f33"
}

rule MalwareBazaar_Mirai_038_02fae52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd"
    family = "Mirai"
    file_name = "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:41:01"
  condition:
    hash.sha256(0, filesize) == "02fae52adc28a56c65b55feef0ed6814d26627bb95d772fde7d586c45aead8fd"
}

rule MalwareBazaar_Mirai_039_f417ce91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8"
    family = "Mirai"
    file_name = "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:40:56"
  condition:
    hash.sha256(0, filesize) == "f417ce91cb83439e3ca4a8b2fe15420ace2a6de0bc5ac628525842b3812cb3c8"
}

rule MalwareBazaar_Mirai_040_61e46199
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d"
    family = "Mirai"
    file_name = "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:40:45"
  condition:
    hash.sha256(0, filesize) == "61e461992a73559c092a22b2d2c8d19d7f5739f2c238faf1b05a6ec8cd10c19d"
}

rule MalwareBazaar_unknown_041_915953d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "915953d2eba9eb21ee77ae729548f8529d323725946e04c08a3875cd63ca6925"
    family = "unknown"
    file_name = "ziomzpihivrtvhyhayzz.exe"
    file_type = "exe"
    first_seen = "2026-08-19 20:40:08"
  condition:
    hash.sha256(0, filesize) == "915953d2eba9eb21ee77ae729548f8529d323725946e04c08a3875cd63ca6925"
}

rule MalwareBazaar_unknown_042_772568e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "772568e499ecf3080396aecdbedf27e00770888e643b724269a569ca132d2ae9"
    family = "unknown"
    file_name = "sh.any"
    file_type = "exe"
    first_seen = "2026-08-19 20:39:46"
  condition:
    hash.sha256(0, filesize) == "772568e499ecf3080396aecdbedf27e00770888e643b724269a569ca132d2ae9"
}

rule MalwareBazaar_Mirai_043_91448844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "914488444166bc2dfd9ac9dfbc060c0dabc4b8997d07c6bb1e42cf1ee1c5ba1a"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-08-19 20:39:39"
  condition:
    hash.sha256(0, filesize) == "914488444166bc2dfd9ac9dfbc060c0dabc4b8997d07c6bb1e42cf1ee1c5ba1a"
}

rule MalwareBazaar_Mirai_044_595d2c22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "595d2c2250abaf70cc91cd6b316966f6ba7569dcdd6c252d11d1ef374e25267b"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-08-19 20:38:59"
  condition:
    hash.sha256(0, filesize) == "595d2c2250abaf70cc91cd6b316966f6ba7569dcdd6c252d11d1ef374e25267b"
}

rule MalwareBazaar_Mirai_045_a46966a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a46966a446f1d97df08bcaa347033ab4694ad19f58033fd2ba0b8bd2318cb7ed"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-19 20:36:43"
  condition:
    hash.sha256(0, filesize) == "a46966a446f1d97df08bcaa347033ab4694ad19f58033fd2ba0b8bd2318cb7ed"
}

rule MalwareBazaar_Mirai_046_8a0e0d1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a0e0d1bf2b530aa53ca31e661a34edaf4dff95d1041dabffcac799c7f001933"
    family = "Mirai"
    file_name = "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:36:41"
  condition:
    hash.sha256(0, filesize) == "8a0e0d1bf2b530aa53ca31e661a34edaf4dff95d1041dabffcac799c7f001933"
}

rule MalwareBazaar_Mirai_047_524172cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524172cff3004980870ed211cb98281964fa7d1b4f42a4bd449c549002846208"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-19 20:36:04"
  condition:
    hash.sha256(0, filesize) == "524172cff3004980870ed211cb98281964fa7d1b4f42a4bd449c549002846208"
}

rule MalwareBazaar_Mirai_048_46c10cf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7"
    family = "Mirai"
    file_name = "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 20:35:44"
  condition:
    hash.sha256(0, filesize) == "46c10cf65045f2aef700bac3f5deb50470b24fb017995bc977185fc100bbdaf7"
}

rule MalwareBazaar_DCRat_049_24fdc482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24fdc48249a04de295cbcc222a9da62ecffdf60cee25c3879bf12ccab3393282"
    family = "DCRat"
    file_name = "19218b199b1706d1e1f4416ffb1b27cf.exe"
    file_type = "exe"
    first_seen = "2026-08-19 20:35:09"
  condition:
    hash.sha256(0, filesize) == "24fdc48249a04de295cbcc222a9da62ecffdf60cee25c3879bf12ccab3393282"
}

rule MalwareBazaar_Mirai_050_41097031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41097031ebd7827a60bac14e80a4032f00d11a1d3f0bdb2e0aea7e0a5bd69d00"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-08-19 20:30:58"
  condition:
    hash.sha256(0, filesize) == "41097031ebd7827a60bac14e80a4032f00d11a1d3f0bdb2e0aea7e0a5bd69d00"
}

rule MalwareBazaar_Mirai_051_b6485bb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6485bb24becb01de3319bc543c026f2b22695146dca3447143384ed92f6933a"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-08-19 20:29:51"
  condition:
    hash.sha256(0, filesize) == "b6485bb24becb01de3319bc543c026f2b22695146dca3447143384ed92f6933a"
}

rule MalwareBazaar_unknown_052_44fe967d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44fe967dbea2200187ed5859ee13fbd27a0c4d51bca120d7715246f2f866b13c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-19 20:29:49"
  condition:
    hash.sha256(0, filesize) == "44fe967dbea2200187ed5859ee13fbd27a0c4d51bca120d7715246f2f866b13c"
}

rule MalwareBazaar_RemusStealer_053_d684fb1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d684fb1e82d42041802c676440d58e964b19ae74e8e7669e84d15da1a1e9c7ee"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 20:25:53"
  condition:
    hash.sha256(0, filesize) == "d684fb1e82d42041802c676440d58e964b19ae74e8e7669e84d15da1a1e9c7ee"
}

rule MalwareBazaar_Mirai_054_db0ef37f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db0ef37f0a87b9abb1affd3a5644f90b9cfa0062990f8bf80d6dcbd23c4e89cb"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-08-19 20:24:43"
  condition:
    hash.sha256(0, filesize) == "db0ef37f0a87b9abb1affd3a5644f90b9cfa0062990f8bf80d6dcbd23c4e89cb"
}

rule MalwareBazaar_Mirai_055_9bc7123d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bc7123d4912de9adba9f10d87b1bc1224f5059d730eb7489cb96f07e6a7d37f"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-08-19 20:24:04"
  condition:
    hash.sha256(0, filesize) == "9bc7123d4912de9adba9f10d87b1bc1224f5059d730eb7489cb96f07e6a7d37f"
}

rule MalwareBazaar_unknown_056_907103c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "907103c82012064f629d1ff30afa1277a4b9f4e2d637060a2b917ec5413585f6"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-08-19 20:24:03"
  condition:
    hash.sha256(0, filesize) == "907103c82012064f629d1ff30afa1277a4b9f4e2d637060a2b917ec5413585f6"
}

rule MalwareBazaar_Mirai_057_deb1a4ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deb1a4ed15b00fa6f2ee706cd9aae50d8bd8a5efda0a608e27fc4bb05c0972c9"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-19 20:21:07"
  condition:
    hash.sha256(0, filesize) == "deb1a4ed15b00fa6f2ee706cd9aae50d8bd8a5efda0a608e27fc4bb05c0972c9"
}

rule MalwareBazaar_unknown_058_fe4ff488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe4ff488b8958f33957264ae55a15bfd5640b495355e13db95275a9ddb7dbbd6"
    family = "unknown"
    file_name = "b.py"
    file_type = "unknown"
    first_seen = "2026-08-19 20:20:00"
  condition:
    hash.sha256(0, filesize) == "fe4ff488b8958f33957264ae55a15bfd5640b495355e13db95275a9ddb7dbbd6"
}

rule MalwareBazaar_Mirai_059_d7fb7535
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7fb753535b2a343489b29aa769b9550da565c5d91b99e56f04852d8e7290585"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-19 20:18:37"
  condition:
    hash.sha256(0, filesize) == "d7fb753535b2a343489b29aa769b9550da565c5d91b99e56f04852d8e7290585"
}

rule MalwareBazaar_Mirai_060_8a7c4e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a7c4e39d1818981f48bcb7537136da3a358156b2521728fc4108dd86b1c6c82"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-19 20:17:56"
  condition:
    hash.sha256(0, filesize) == "8a7c4e39d1818981f48bcb7537136da3a358156b2521728fc4108dd86b1c6c82"
}

rule MalwareBazaar_Mirai_061_fcb7a789
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcb7a789e1211bda2c3e6e55d1fb0f69f7b86e376569a3da6502054573c93f82"
    family = "Mirai"
    file_name = "flutter.m68k"
    file_type = "elf"
    first_seen = "2026-08-19 20:14:47"
  condition:
    hash.sha256(0, filesize) == "fcb7a789e1211bda2c3e6e55d1fb0f69f7b86e376569a3da6502054573c93f82"
}

rule MalwareBazaar_unknown_062_7869ebdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7869ebdc68d79aaa51b73b417d5d6a107ae355761b91f4303c388f4635ff8481"
    family = "unknown"
    file_name = "HCGFhPaIrP.vbs"
    file_type = "vbs"
    first_seen = "2026-08-19 20:13:59"
  condition:
    hash.sha256(0, filesize) == "7869ebdc68d79aaa51b73b417d5d6a107ae355761b91f4303c388f4635ff8481"
}

rule MalwareBazaar_Mirai_063_3ed960da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ed960da28f701deef8733e265a63a9471612611abdfc1b5e417617a744e5416"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-19 20:06:34"
  condition:
    hash.sha256(0, filesize) == "3ed960da28f701deef8733e265a63a9471612611abdfc1b5e417617a744e5416"
}

rule MalwareBazaar_Mirai_064_8dfc0d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dfc0d4d635338474f65c1c6aaecd9238761a669179d9bfc70341e5c8b7ae6c5"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-19 20:06:15"
  condition:
    hash.sha256(0, filesize) == "8dfc0d4d635338474f65c1c6aaecd9238761a669179d9bfc70341e5c8b7ae6c5"
}

rule MalwareBazaar_njrat_065_622ad8a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "622ad8a0eb9290c6c1fb7924f6019e18b34fee8b7583d756f1c8750ed6e793e8"
    family = "njrat"
    file_name = "15d1b26149fde69fc4203df9dfb6f220.exe"
    file_type = "exe"
    first_seen = "2026-08-19 20:00:11"
  condition:
    hash.sha256(0, filesize) == "622ad8a0eb9290c6c1fb7924f6019e18b34fee8b7583d756f1c8750ed6e793e8"
}

rule MalwareBazaar_unknown_066_3e7333a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e7333a7d765a0277a04617c0ed54d2e79ef50e6787462e648a724981218021a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-19 19:59:46"
  condition:
    hash.sha256(0, filesize) == "3e7333a7d765a0277a04617c0ed54d2e79ef50e6787462e648a724981218021a"
}

rule MalwareBazaar_Mirai_067_77ea6c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77ea6c1d964d7bf9a1bdb5a7a34b6f707065235554ff7fc58dd2de2def70c53a"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-19 19:57:39"
  condition:
    hash.sha256(0, filesize) == "77ea6c1d964d7bf9a1bdb5a7a34b6f707065235554ff7fc58dd2de2def70c53a"
}

rule MalwareBazaar_Mirai_068_5bb9a233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb9a2335169cf8237cfa2e254340d6475788a091dd9be2e3a690e018fcb7ef0"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-19 19:56:52"
  condition:
    hash.sha256(0, filesize) == "5bb9a2335169cf8237cfa2e254340d6475788a091dd9be2e3a690e018fcb7ef0"
}

rule MalwareBazaar_unknown_069_a7a35912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7a3591258756996e1e0a2a8dd1722cd8d5f741c0ce5492dba1eebc0e52dfa32"
    family = "unknown"
    file_name = "ziomzpihivrtvhyhayzz.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:50:01"
  condition:
    hash.sha256(0, filesize) == "a7a3591258756996e1e0a2a8dd1722cd8d5f741c0ce5492dba1eebc0e52dfa32"
}

rule MalwareBazaar_unknown_070_87e6859c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87e6859c66447242daaf9e0fa55d608bce1c572082e2e0d117d81a13663fc318"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 19:38:03"
  condition:
    hash.sha256(0, filesize) == "87e6859c66447242daaf9e0fa55d608bce1c572082e2e0d117d81a13663fc318"
}

rule MalwareBazaar_unknown_071_5c1f8f83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c1f8f839d1d333582b71afb3b7e64bf5d9be450dfeee1fcdb4b0ead017c5bc2"
    family = "unknown"
    file_name = "Toolkit_v12.5.zip"
    file_type = "zip"
    first_seen = "2026-08-19 19:29:47"
  condition:
    hash.sha256(0, filesize) == "5c1f8f839d1d333582b71afb3b7e64bf5d9be450dfeee1fcdb4b0ead017c5bc2"
}

rule MalwareBazaar_unknown_072_43f1cf98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43f1cf980546901863c625ab3fa04961b720167421f78fe6558b204cf081f826"
    family = "unknown"
    file_name = "XML Files.zip"
    file_type = "zip"
    first_seen = "2026-08-19 19:20:44"
  condition:
    hash.sha256(0, filesize) == "43f1cf980546901863c625ab3fa04961b720167421f78fe6558b204cf081f826"
}

rule MalwareBazaar_unknown_073_e61ada77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e61ada7705acfb837faa1fd96bc3f733ee174a3562e423ccd2707ddb15cccb8f"
    family = "unknown"
    file_name = "spxploy.vbs"
    file_type = "vbs"
    first_seen = "2026-08-19 19:13:45"
  condition:
    hash.sha256(0, filesize) == "e61ada7705acfb837faa1fd96bc3f733ee174a3562e423ccd2707ddb15cccb8f"
}

rule MalwareBazaar_unknown_074_b0206e3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0206e3effd345734a191751fd7dcf412e1264e5a9671347540183dc37507b4c"
    family = "unknown"
    file_name = "sp.zip"
    file_type = "zip"
    first_seen = "2026-08-19 19:13:42"
  condition:
    hash.sha256(0, filesize) == "b0206e3effd345734a191751fd7dcf412e1264e5a9671347540183dc37507b4c"
}

rule MalwareBazaar_unknown_075_1bc067d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bc067d7bc73a5205544164b122634bf25d98c2b6e81a3353b895aa9d0d3707c"
    family = "unknown"
    file_name = "s.bat"
    file_type = "bat"
    first_seen = "2026-08-19 19:13:23"
  condition:
    hash.sha256(0, filesize) == "1bc067d7bc73a5205544164b122634bf25d98c2b6e81a3353b895aa9d0d3707c"
}

rule MalwareBazaar_RemusStealer_076_4f92f1b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f92f1b658856b2662100c26dcd5f81525a74482b4fdebb16923ec27234f0a7e"
    family = "RemusStealer"
    file_name = "r843.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:13:21"
  condition:
    hash.sha256(0, filesize) == "4f92f1b658856b2662100c26dcd5f81525a74482b4fdebb16923ec27234f0a7e"
}

rule MalwareBazaar_unknown_077_cd2cbf32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd2cbf3277a263102361c9ee187e542c15ee02bc257dc17cd207f355f1d0f959"
    family = "unknown"
    file_name = "ohijfalqvzldlhaqw.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:13:18"
  condition:
    hash.sha256(0, filesize) == "cd2cbf3277a263102361c9ee187e542c15ee02bc257dc17cd207f355f1d0f959"
}

rule MalwareBazaar_unknown_078_6f6cb5d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f6cb5d3dbb2c6df2cedb919626fc5f273aba90eda86c9efd17d9af3855de79b"
    family = "unknown"
    file_name = "niceworking.vbe"
    file_type = "vbe"
    first_seen = "2026-08-19 19:13:13"
  condition:
    hash.sha256(0, filesize) == "6f6cb5d3dbb2c6df2cedb919626fc5f273aba90eda86c9efd17d9af3855de79b"
}

rule MalwareBazaar_MeshAgent_079_3c6ee1de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c6ee1def9b061e4591fd063ab29ea0df40e205a9c7540e23716f32313568f32"
    family = "MeshAgent"
    file_name = "meshagents"
    file_type = "exe"
    first_seen = "2026-08-19 19:13:10"
  condition:
    hash.sha256(0, filesize) == "3c6ee1def9b061e4591fd063ab29ea0df40e205a9c7540e23716f32313568f32"
}

rule MalwareBazaar_unknown_080_a367a461
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a367a461a57c1dd3f2ce3a975ea950d37023870cc9083a54d471ff3cc266b43b"
    family = "unknown"
    file_name = "load.bat"
    file_type = "bat"
    first_seen = "2026-08-19 19:13:06"
  condition:
    hash.sha256(0, filesize) == "a367a461a57c1dd3f2ce3a975ea950d37023870cc9083a54d471ff3cc266b43b"
}

rule MalwareBazaar_unknown_081_8c23cd31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c23cd316bef30fbed31b835fd17ab0b21f0bcee84d69efc0d984db87fb58418"
    family = "unknown"
    file_name = "iwantsomethingbetterformegetbackgoodthings.vbe"
    file_type = "vbe"
    first_seen = "2026-08-19 19:13:02"
  condition:
    hash.sha256(0, filesize) == "8c23cd316bef30fbed31b835fd17ab0b21f0bcee84d69efc0d984db87fb58418"
}

rule MalwareBazaar_unknown_082_4d2842d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d2842d0602fe8045297818515821c6646cc01d3bf3e684a5a888e7b25663965"
    family = "unknown"
    file_name = "img_203145.png"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:59"
  condition:
    hash.sha256(0, filesize) == "4d2842d0602fe8045297818515821c6646cc01d3bf3e684a5a888e7b25663965"
}

rule MalwareBazaar_RemcosRAT_083_0bbc781a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bbc781ab36954da7bd6108a3cd59fd5b1d0b18992e1f7de9abc147e30c83d80"
    family = "RemcosRAT"
    file_name = "goodthingsarebestformehappeninggood.vbe"
    file_type = "vbe"
    first_seen = "2026-08-19 19:12:48"
  condition:
    hash.sha256(0, filesize) == "0bbc781ab36954da7bd6108a3cd59fd5b1d0b18992e1f7de9abc147e30c83d80"
}

rule MalwareBazaar_unknown_084_5963a949
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5963a9491c91eae44384e239284fdc74dc3db9ee1b13c24eccc516ece350df34"
    family = "unknown"
    file_name = "goodcommuncaitionskilldevleipedfromthegood.js"
    file_type = "js"
    first_seen = "2026-08-19 19:12:44"
  condition:
    hash.sha256(0, filesize) == "5963a9491c91eae44384e239284fdc74dc3db9ee1b13c24eccc516ece350df34"
}

rule MalwareBazaar_unknown_085_60f32804
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60f3280493c50acf8ccc3b128177e714a7dd58dc5f89871ad6683ab1539b382c"
    family = "unknown"
    file_name = "go_b3.bat"
    file_type = "bat"
    first_seen = "2026-08-19 19:12:40"
  condition:
    hash.sha256(0, filesize) == "60f3280493c50acf8ccc3b128177e714a7dd58dc5f89871ad6683ab1539b382c"
}

rule MalwareBazaar_unknown_086_cc2b96a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc2b96a6c355518992425086221902594f98c16b2825f517d961f35368bba14d"
    family = "unknown"
    file_name = "crypted.ps1.5"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:36"
  condition:
    hash.sha256(0, filesize) == "cc2b96a6c355518992425086221902594f98c16b2825f517d961f35368bba14d"
}

rule MalwareBazaar_unknown_087_d1aaf735
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1aaf73552c77ab6bea5c26e39e7d2d303b395314c3abe7fd426de90463c835d"
    family = "unknown"
    file_name = "crypted.ps1.4"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:33"
  condition:
    hash.sha256(0, filesize) == "d1aaf73552c77ab6bea5c26e39e7d2d303b395314c3abe7fd426de90463c835d"
}

rule MalwareBazaar_unknown_088_f0262f2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0262f2f37f5557cca06d49b951ab28c49e5796fba28365a117abaed031aa53a"
    family = "unknown"
    file_name = "crypted.ps1.3"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:28"
  condition:
    hash.sha256(0, filesize) == "f0262f2f37f5557cca06d49b951ab28c49e5796fba28365a117abaed031aa53a"
}

rule MalwareBazaar_unknown_089_adfefc26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adfefc2614695191b1a6e4050e53784a56204f03da3f1a6c55a90ae08ed16e72"
    family = "unknown"
    file_name = "crypted.ps1.2"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:24"
  condition:
    hash.sha256(0, filesize) == "adfefc2614695191b1a6e4050e53784a56204f03da3f1a6c55a90ae08ed16e72"
}

rule MalwareBazaar_unknown_090_4d70fd13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d70fd13a1aa624abe0b5941dd3130f28e357daa644811550716197491a897c4"
    family = "unknown"
    file_name = "crypted.ps1.1"
    file_type = "unknown"
    first_seen = "2026-08-19 19:12:20"
  condition:
    hash.sha256(0, filesize) == "4d70fd13a1aa624abe0b5941dd3130f28e357daa644811550716197491a897c4"
}

rule MalwareBazaar_unknown_091_80206973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "802069736d28e5c16bce132a1cfe905f6f9c7ae44500cb32c3a34e93452400d6"
    family = "unknown"
    file_name = "battlebot.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:12:12"
  condition:
    hash.sha256(0, filesize) == "802069736d28e5c16bce132a1cfe905f6f9c7ae44500cb32c3a34e93452400d6"
}

rule MalwareBazaar_ConnectWise_092_98fd0403
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98fd04031af897a657b71eebc1a3d6576f78d52a497c11868fbbce1dda893fbf"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-08-19 19:12:07"
  condition:
    hash.sha256(0, filesize) == "98fd04031af897a657b71eebc1a3d6576f78d52a497c11868fbbce1dda893fbf"
}

rule MalwareBazaar_ConnectWise_093_2671b93e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2671b93e5dccb24ce9d3461a6f392f1251e78d3e11b6268475a51bed4298dffd"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:12:03"
  condition:
    hash.sha256(0, filesize) == "2671b93e5dccb24ce9d3461a6f392f1251e78d3e11b6268475a51bed4298dffd"
}

rule MalwareBazaar_unknown_094_f94db5a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94db5a93b19e1800be99cb0be2fb21794d3c89ccb588b53739a62c587bc20e6"
    family = "unknown"
    file_name = "OCUDLOMO.msi"
    file_type = "msi"
    first_seen = "2026-08-19 19:11:58"
  condition:
    hash.sha256(0, filesize) == "f94db5a93b19e1800be99cb0be2fb21794d3c89ccb588b53739a62c587bc20e6"
}

rule MalwareBazaar_unknown_095_417f3968
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "417f396852e6b1f4360ff1e4c16b85bd65ba46faa5c71fb97816b0a796d8055d"
    family = "unknown"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:11:54"
  condition:
    hash.sha256(0, filesize) == "417f396852e6b1f4360ff1e4c16b85bd65ba46faa5c71fb97816b0a796d8055d"
}

rule MalwareBazaar_unknown_096_80719d8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80719d8ef5d25edada79486feff7f73f914409c24faf0979ab805010c0140663"
    family = "unknown"
    file_name = "Bembemi.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:11:50"
  condition:
    hash.sha256(0, filesize) == "80719d8ef5d25edada79486feff7f73f914409c24faf0979ab805010c0140663"
}

rule MalwareBazaar_unknown_097_0ee2eb56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ee2eb5659a3fe9ff41b0b80d8dc0f5f85b2127111f60860d024f74d9719ca77"
    family = "unknown"
    file_name = "Av.scr"
    file_type = "pdf"
    first_seen = "2026-08-19 19:11:34"
  condition:
    hash.sha256(0, filesize) == "0ee2eb5659a3fe9ff41b0b80d8dc0f5f85b2127111f60860d024f74d9719ca77"
}

rule MalwareBazaar_unknown_098_aaeae4c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaeae4c452096b11902e0077e6fab22aa3d1f50266edb2643e38278e0f5c6c0c"
    family = "unknown"
    file_name = "BAC_PC壳.exe"
    file_type = "exe"
    first_seen = "2026-08-19 19:11:22"
  condition:
    hash.sha256(0, filesize) == "aaeae4c452096b11902e0077e6fab22aa3d1f50266edb2643e38278e0f5c6c0c"
}

rule MalwareBazaar_Mirai_099_9629db96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9629db9638a8145583ceb452d0328fe88af94fded7c1f228c8adf4240399c15d"
    family = "Mirai"
    file_name = "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19.elf"
    file_type = "elf"
    first_seen = "2026-08-19 18:56:46"
  condition:
    hash.sha256(0, filesize) == "9629db9638a8145583ceb452d0328fe88af94fded7c1f228c8adf4240399c15d"
}

rule MalwareBazaar_Mirai_100_ad3978ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19"
    family = "Mirai"
    file_name = "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19.elf"
    file_type = "elf"
    first_seen = "2026-08-19 18:55:46"
  condition:
    hash.sha256(0, filesize) == "ad3978ae70de2c57cba34a0f18bb06ac3b4e3cda0cb357ecdfe0bb08fd157f19"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

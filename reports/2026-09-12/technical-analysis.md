# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-12

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 585 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 585 |
| Unique family labels | 8 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 74 |
| Mirai | 13 |
| ConnectWise | 5 |
| ValleyRAT | 2 |
| Gh0stRAT | 2 |
| GoToResolve | 2 |
| SimpleHelp | 1 |
| RemusStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 46 |
| exe | 20 |
| unknown | 13 |
| sh | 12 |
| msi | 4 |
| vbs | 2 |
| apk | 1 |
| js | 1 |
| iso | 1 |

## Per-Sample Analysis

### Sample 1: `99c90c3796f9d021`

| Field | Value |
|---|---|
| SHA-256 | `99c90c3796f9d0212669d4a4d4f3749fddb890fdb570cd0e3165bb8870a2136a` |
| Family label | `unknown` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-09-12 04:38:13` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9f29135c5e3d2028d646a26a339521f` |
| SHA-1 | `3c2e7f1c513ea1069023e511ebb0676bc586e428` |
| SHA-256 | `99c90c3796f9d0212669d4a4d4f3749fddb890fdb570cd0e3165bb8870a2136a` |
| SHA3-384 | `c95e78369f3298237deba8ac8101062d4c0a68bd303315d1c35f069ed534ebc3da36b379a15e7b4574cc3150b73eebbb` |
| TLSH | `T183D312C45BF78F13E2C2CFB3E4970346BB939E5B56C30B298A9DE654120816CB706B65` |
| SSDEEP | `3072:5NKgS4rSEthVW7cDKmVwizNQKJjUmAUDhg75yGg85ucIz19GyrXQ:55uENPumZQKqMDhSHjTGDXQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_99c90c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99c90c3796f9d0212669d4a4d4f3749fddb890fdb570cd0e3165bb8870a2136a"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-09-12 04:38:13"
  condition:
    hash.sha256(0, filesize) == "99c90c3796f9d0212669d4a4d4f3749fddb890fdb570cd0e3165bb8870a2136a"
}
```

### Sample 2: `b98ed7a5c645421a`

| Field | Value |
|---|---|
| SHA-256 | `b98ed7a5c645421acd5462f2b3ed759087bfbe16890fe4c471e76c8d1ab35c8a` |
| Family label | `Mirai` |
| File name | `libwind.so` |
| File type | `elf` |
| First seen | `2026-09-12 04:32:41` |
| Reporter | `deepfield` |
| Tags | `ddos, elf, Mirai, mossadproxy` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23e6ec5858d02b141378721097fafe87` |
| SHA-1 | `1bf484e63a8d4e2aa17d7dc0a5ca24d0d0841f59` |
| SHA-256 | `b98ed7a5c645421acd5462f2b3ed759087bfbe16890fe4c471e76c8d1ab35c8a` |
| SHA3-384 | `1dd479839380f0140cbe31300718e54000e0177b320e87e3ea5a340f02a79edf75a7da668d5a90c47cc2a06675359704` |
| TLSH | `T162630AA9F951C512C1E411BAA84A85DC331313ACC3EB7353CE15CB3639EE5AD0E3AB59` |
| TELFHASH | `t1fce0ab00bc75ca1989c3abb0dcac47b09602a11311628724cf00d3d0c83f148a30ce6b` |
| SSDEEP | `1536:MR+qIJPSJkNWbCXP/TxWylVPR51YEj2bv6pSa:MRdVJdiLPL1FKha` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_b98ed7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98ed7a5c645421acd5462f2b3ed759087bfbe16890fe4c471e76c8d1ab35c8a"
    family = "Mirai"
    file_name = "libwind.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:41"
  condition:
    hash.sha256(0, filesize) == "b98ed7a5c645421acd5462f2b3ed759087bfbe16890fe4c471e76c8d1ab35c8a"
}
```

### Sample 3: `5002282edb86e86f`

| Field | Value |
|---|---|
| SHA-256 | `5002282edb86e86fd7d7eedd8b3bd2444390eec0d18e93641d23c89cdba1f9ef` |
| Family label | `Mirai` |
| File name | `libyahu.so` |
| File type | `elf` |
| First seen | `2026-09-12 04:32:39` |
| Reporter | `deepfield` |
| Tags | `ddos, elf, Mirai, vibenet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `835980375873b6af6ceacb7af05cfbe3` |
| SHA-1 | `9ccb733b6fa448a42b86eb13fd088f77beba1bdd` |
| SHA-256 | `5002282edb86e86fd7d7eedd8b3bd2444390eec0d18e93641d23c89cdba1f9ef` |
| SHA3-384 | `2166e98fecc04ca35e3b0c364dbb8dd2653c91ba17825fd07574c180cd17efecbee72e01a5fae9bbab609369d2e7e8fd` |
| TLSH | `T1417409A6FC42D981C5D429FAFB1EC2C833031378E3DA7112AD168B25A5CF55D4E3EA91` |
| TELFHASH | `t1ae612391ffad11b9b3c380e452fae02656ab32dd5b0439664614bbbf2d42dc03467c07` |
| SSDEEP | `6144:qT/k5Qg5p7dJol2qIB9/Wy3cmw3ntxrRhklTLTvb8Pi7j9Jj6OP:E/O/Li/APw3r9he7FJjd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_5002282e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5002282edb86e86fd7d7eedd8b3bd2444390eec0d18e93641d23c89cdba1f9ef"
    family = "Mirai"
    file_name = "libyahu.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:39"
  condition:
    hash.sha256(0, filesize) == "5002282edb86e86fd7d7eedd8b3bd2444390eec0d18e93641d23c89cdba1f9ef"
}
```

### Sample 4: `da37e1eef108b5eb`

| Field | Value |
|---|---|
| SHA-256 | `da37e1eef108b5eba7563e5b1f0950dd1852bf9cf921910b24b57291806c375f` |
| Family label | `unknown` |
| File name | `deepfield.so` |
| File type | `elf` |
| First seen | `2026-09-12 04:32:36` |
| Reporter | `deepfield` |
| Tags | `ddos, drifter, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4044d42df19e913e79f19ca07d1e541` |
| SHA-1 | `a8130a274e38e4e8ecc893a9982288637934ac05` |
| SHA-256 | `da37e1eef108b5eba7563e5b1f0950dd1852bf9cf921910b24b57291806c375f` |
| SHA3-384 | `cf0209d8ba4d4d7d2f4dfa5a4aa97932003d810bdc4284d3d1091319843da8f8a8396e1489a1dd1d00bb50b207c3508a` |
| TLSH | `T13E743B65FC819B91D6D12EBEFF1E824933130B78F2DE7222AD155B3463CB85A0E7A501` |
| TELFHASH | `t1b3d02b548c6c2cb826c8d54a728cd87409711007777c7d4837711b95ec804c398114a9` |
| SSDEEP | `6144:x89Jl7rZvu/ZNd3BgMt6DCqAxvh6PTWxLf9OAReBJ8tqYc94plAFyul2pxEtVaRE:x8bl7rxu/ZP3B1cAzUTWxLf9lReB+tqD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_da37e1ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da37e1eef108b5eba7563e5b1f0950dd1852bf9cf921910b24b57291806c375f"
    family = "unknown"
    file_name = "deepfield.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:36"
  condition:
    hash.sha256(0, filesize) == "da37e1eef108b5eba7563e5b1f0950dd1852bf9cf921910b24b57291806c375f"
}
```

### Sample 5: `b200ab6d281055e1`

| Field | Value |
|---|---|
| SHA-256 | `b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-12 04:32:33` |
| Reporter | `deepfield` |
| Tags | `ddos, elf, Mirai, potassium` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f04a90bc8845d25005ada07ced24948` |
| SHA-1 | `643e4c8997bd3a39fc16933767648ed4e7a9cb77` |
| SHA-256 | `b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb` |
| SHA3-384 | `d57922b028a3de77bb8731523d4b6d64db460c980feaa74e7ec8957339ed8dcf83d8563af4a0f385f331c22ce9aa7129` |
| TLSH | `T16C542A66BD819B95D5C52ABFFF5E824933172BBCE2EE3102DD145F2137CA84A0E7A101` |
| SSDEEP | `6144:7N5qMm7YtWiBWlZm2LFU+0dDhlIWx26EMD3VagWrzMyWTP9yPBqccA+:7dtWiBWHHLFgd4q0MD3Va9rzMyWAZZc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_b200ab6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:33"
  condition:
    hash.sha256(0, filesize) == "b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb"
}
```

### Sample 6: `895a9274620e8d9c`

| Field | Value |
|---|---|
| SHA-256 | `895a9274620e8d9c48ddf330df8b9d7331322ea659c35d8808c381add741a89a` |
| Family label | `Mirai` |
| File name | `com.imjustafriendlyguy.firmware.apk` |
| File type | `apk` |
| First seen | `2026-09-12 04:32:30` |
| Reporter | `deepfield` |
| Tags | `apk, cecbot, ddos, Mirai, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1177ec5a8ab84ad460c99f57578237bc` |
| SHA-1 | `5f060c8f69d95df3b0d40e9aadb4562a52a9769a` |
| SHA-256 | `895a9274620e8d9c48ddf330df8b9d7331322ea659c35d8808c381add741a89a` |
| SHA3-384 | `c647f1a77813ce34fcb996eec8ce3f8dfe21e969947ea041e29b96788e3fbefd5c2a820e6d4d54aedf0c2f6b4ae8ef74` |
| TLSH | `T19B241203A64B0A3EFF91EDB9B67889F35B4CA48619376F5E6A00A55E2C435470FC14F2` |
| SSDEEP | `6144:J5B7z0mu3qIaCGxjD2Szn9lxBDtPUECeAPHuqg1O:J5B7z0mu3qIa3xpznlBpSeAP3g1O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_895a9274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "895a9274620e8d9c48ddf330df8b9d7331322ea659c35d8808c381add741a89a"
    family = "Mirai"
    file_name = "com.imjustafriendlyguy.firmware.apk"
    file_type = "apk"
    first_seen = "2026-09-12 04:32:30"
  condition:
    hash.sha256(0, filesize) == "895a9274620e8d9c48ddf330df8b9d7331322ea659c35d8808c381add741a89a"
}
```

### Sample 7: `086c60e9b4fe2ea1`

| Field | Value |
|---|---|
| SHA-256 | `086c60e9b4fe2ea121130220fcae8185e2b3b7734a8208f434f064b654e7d872` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 04:28:26` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9aa6d446b2797f4c91661218e5d7801a` |
| SHA-256 | `086c60e9b4fe2ea121130220fcae8185e2b3b7734a8208f434f064b654e7d872` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_086c60e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086c60e9b4fe2ea121130220fcae8185e2b3b7734a8208f434f064b654e7d872"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 04:28:26"
  condition:
    hash.sha256(0, filesize) == "086c60e9b4fe2ea121130220fcae8185e2b3b7734a8208f434f064b654e7d872"
}
```

### Sample 8: `40f9fdac9ab5160d`

| Field | Value |
|---|---|
| SHA-256 | `40f9fdac9ab5160d7e596c163a3868efbfdce437fc9e99815fdb6dc469029a2a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-12 04:21:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `883b8ef3f76a1956bf162c3744f1658f` |
| SHA-1 | `8924c6ce081e567b850e103e4ac57691c60e4833` |
| SHA-256 | `40f9fdac9ab5160d7e596c163a3868efbfdce437fc9e99815fdb6dc469029a2a` |
| SHA3-384 | `acca1bab1f865f2fa79c6ba4ccd9a668994fdc3b5334afd3b5489d731e89e2ce0b3f54778b421f7a14dc3b70fb06fc99` |
| TLSH | `T185236C651A857C24AA98C4371D7E2F0CBDAD43E6324492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:zXRWNGxV59GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Nlxscr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_40f9fdac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f9fdac9ab5160d7e596c163a3868efbfdce437fc9e99815fdb6dc469029a2a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 04:21:21"
  condition:
    hash.sha256(0, filesize) == "40f9fdac9ab5160d7e596c163a3868efbfdce437fc9e99815fdb6dc469029a2a"
}
```

### Sample 9: `e870ba426cd9bd85`

| Field | Value |
|---|---|
| SHA-256 | `e870ba426cd9bd8542b413641a456b6f1eab480a88eb2d83d644c1461a524919` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-12 04:21:20` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af87afd06c860d746b2971d51a6398f3` |
| SHA-1 | `e441690e9de46363ae221275522b23c36c981cb2` |
| SHA-256 | `e870ba426cd9bd8542b413641a456b6f1eab480a88eb2d83d644c1461a524919` |
| SHA3-384 | `96770a3d5c713a5d289e2032f8201a61bc6ec0d732aaaa7a5f05cda8214a13f4e37e69f05a22f3cb5f4584adfcb16aaa` |
| TLSH | `T1E6C27C95AA867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:m8vCB+25j6es8RJX9FYpMSUpi+20qUpi+20YQX:m8l25JJxd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_e870ba42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e870ba426cd9bd8542b413641a456b6f1eab480a88eb2d83d644c1461a524919"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 04:21:20"
  condition:
    hash.sha256(0, filesize) == "e870ba426cd9bd8542b413641a456b6f1eab480a88eb2d83d644c1461a524919"
}
```

### Sample 10: `48bc5bcd4ef81298`

| Field | Value |
|---|---|
| SHA-256 | `48bc5bcd4ef81298eacb98ab6f63cd9c3bdfadd917dea63c4af0ee470ea2cd18` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 04:19:32` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e38a3c52e123dc7b05b8dda759a69a29` |
| SHA-256 | `48bc5bcd4ef81298eacb98ab6f63cd9c3bdfadd917dea63c4af0ee470ea2cd18` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_48bc5bcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48bc5bcd4ef81298eacb98ab6f63cd9c3bdfadd917dea63c4af0ee470ea2cd18"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 04:19:32"
  condition:
    hash.sha256(0, filesize) == "48bc5bcd4ef81298eacb98ab6f63cd9c3bdfadd917dea63c4af0ee470ea2cd18"
}
```

### Sample 11: `d7079114f00c0265`

| Field | Value |
|---|---|
| SHA-256 | `d7079114f00c0265e3553cd10f8816298c806a8b37402bfb4192ae9b8b9fc951` |
| Family label | `unknown` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-09-12 04:10:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `585c1b363280b085c07e50d00d1cdf61` |
| SHA-1 | `38f29385aa488aa2a623239f9fa0c7d15d67f014` |
| SHA-256 | `d7079114f00c0265e3553cd10f8816298c806a8b37402bfb4192ae9b8b9fc951` |
| SHA3-384 | `a9dbfa048371f213512730ab69f1b28f27633611fd4dc68e2986f1b799bc8660a278093cd612744a42e02f04dae8b098` |
| TLSH | `T1AAB31213C101BCECDB97D5BA9E3DA29EBA1B3C1475B87D179501BE2D3B26E104613D06` |
| TELFHASH | `t1d6c0129213103ce223070c017221d1aace020873ba213a2d33398cf8aa20b058901010` |
| SSDEEP | `1536:M+U8gfI3DW+oVd2cW1CwrIRmAR+65pLvfPGL3JO4Wc/I4kQQGU9WSCLwWcLOyitq:M+IxdFBpcKdJvfPGlgQQGECLwDdyo9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_d7079114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7079114f00c0265e3553cd10f8816298c806a8b37402bfb4192ae9b8b9fc951"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-09-12 04:10:39"
  condition:
    hash.sha256(0, filesize) == "d7079114f00c0265e3553cd10f8816298c806a8b37402bfb4192ae9b8b9fc951"
}
```

### Sample 12: `d3c34baf4731aeff`

| Field | Value |
|---|---|
| SHA-256 | `d3c34baf4731aeffc5be0d1b6d2eb4ca4bddf35af1a1a79877bdc687189f857f` |
| Family label | `unknown` |
| File name | `libsupport.so` |
| File type | `elf` |
| First seen | `2026-09-12 04:09:25` |
| Reporter | `deepfield` |
| Tags | `ddos, elf, vibenet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e580ca64e825fe69d65fdfe24cd5eb3` |
| SHA-1 | `5d25d76779e39e9bf8aa6c52fb003d2c9e71c9a5` |
| SHA-256 | `d3c34baf4731aeffc5be0d1b6d2eb4ca4bddf35af1a1a79877bdc687189f857f` |
| SHA3-384 | `a4c0a8a8b94ec1093ec77a62672fb20163793928003f88bf7e1da69174aec2104673441f961b3797e8ecec555fd14a52` |
| TLSH | `T1C5643926FC419B51C5D12EBAFF2E928933130778F3DE71229D1A5B30A78A84B0E7B545` |
| TELFHASH | `t19011d0b504b510d933f5e44990eef2142c6aecad7b9622c645faed4ec473097b810c1f` |
| SSDEEP | `6144:wJxirGnlFqwXnm/mWbqHiW6f8K3UOuzlNp4x5lMPDOyfsK7+iknagOQ/EkkS731i:4nB+oRb4UhpYFKCiknagrEkkS7cu90N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_d3c34baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3c34baf4731aeffc5be0d1b6d2eb4ca4bddf35af1a1a79877bdc687189f857f"
    family = "unknown"
    file_name = "libsupport.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:09:25"
  condition:
    hash.sha256(0, filesize) == "d3c34baf4731aeffc5be0d1b6d2eb4ca4bddf35af1a1a79877bdc687189f857f"
}
```

### Sample 13: `28fd91c15efccb76`

| Field | Value |
|---|---|
| SHA-256 | `28fd91c15efccb7678249f03890952819453df461eef83ef1b12a562f9d35ac4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-12 04:01:26` |
| Reporter | `Bitsight` |
| Tags | `10x09x2026, dropped-by-StealC, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3de59c7196a3da211bf49815d0c10336` |
| SHA-1 | `0f1e55c6975dde1e770033f59c6fd00445c0050a` |
| SHA-256 | `28fd91c15efccb7678249f03890952819453df461eef83ef1b12a562f9d35ac4` |
| SHA3-384 | `5835621d16de5aea1dd0299c31f8567dbd562ba949a0a73ccb1f2941cd2240c8b6aff148fee8663fd3ca4963fdfac6c3` |
| IMPHASH | `56bfda7073ea0a159d22e925194a7054` |
| TLSH | `T166345A1A73A508FBE836823DC4531A05E77678160B61CFAF0764026A6F237D19D3EFA1` |
| SSDEEP | `3072:lu7oXKl1K+qYfWEp8arPGZVGUo3t58TzhqOaMkvygjB3lJ8M3x/P93oMDHqcKdP:AAKlYPYVPK8UEoHgOaMbSpDVKdP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_28fd91c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28fd91c15efccb7678249f03890952819453df461eef83ef1b12a562f9d35ac4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 04:01:26"
  condition:
    hash.sha256(0, filesize) == "28fd91c15efccb7678249f03890952819453df461eef83ef1b12a562f9d35ac4"
}
```

### Sample 14: `5ad6770bf4ad965f`

| Field | Value |
|---|---|
| SHA-256 | `5ad6770bf4ad965f1a280ecc28de35ffa39eb4e174174b968f5dbd56e110f4ab` |
| Family label | `unknown` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-09-12 03:52:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2b25398c2e5897f6ae26a13c9e006cd` |
| SHA-1 | `87efd23ae5ce62e91f502a9bc0371267c2cb5684` |
| SHA-256 | `5ad6770bf4ad965f1a280ecc28de35ffa39eb4e174174b968f5dbd56e110f4ab` |
| SHA3-384 | `4967254b4c5cfb21eefb0c05aef8eca5cae84ff0badf362466962959629ef252f3aa2405ac93d58dfefd5537d1dadf69` |
| TLSH | `T16DB30297EE4136CEC640073E90CBAB007EC1D91278869C7B63D96EAC5B74379B36A1C5` |
| SSDEEP | `1536:u/1ybhNlYrjdHvYZrrV08JogpXe8zNAQ10K4cJcIG2BWyVcH/a0lErgIYygo3:cybHl2xAJrV1PeaAK0K4cOod70w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_5ad6770b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ad6770bf4ad965f1a280ecc28de35ffa39eb4e174174b968f5dbd56e110f4ab"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-09-12 03:52:23"
  condition:
    hash.sha256(0, filesize) == "5ad6770bf4ad965f1a280ecc28de35ffa39eb4e174174b968f5dbd56e110f4ab"
}
```

### Sample 15: `fede8fbf1f1795dd`

| Field | Value |
|---|---|
| SHA-256 | `fede8fbf1f1795ddbd9283c5ad2f74869820759fa49b6adb1113df4e19cca3b6` |
| Family label | `unknown` |
| File name | `ecf4307739ca93f1569ce49377a28b31fe1eb0f44b6950dbaafa1925b24c9752.dll` |
| File type | `exe` |
| First seen | `2026-09-12 03:51:45` |
| Reporter | `Kejult` |
| Tags | `dll, dropper, exe, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6998d99bd449cbea6fe2688751ffe09e` |
| SHA-1 | `65d3bcd087048b0321e2c81425e417adaea23965` |
| SHA-256 | `fede8fbf1f1795ddbd9283c5ad2f74869820759fa49b6adb1113df4e19cca3b6` |
| SHA3-384 | `650e5f37837d97c818d13ea1b2cde850860c70894b765041213bf81ebbbada5386831297422589d160fa64d8f3e53456` |
| IMPHASH | `1e6a4142ad6a521fe1a5012997804f01` |
| TLSH | `T16805122376A411FFD5A6823DD47B2B04A33138230531DB6F13E451AB7F6BB916D2AB10` |
| SSDEEP | `12288:SyLKVHgMAy7jPLVeLe4/9JAS8b8PfO0DyoQv7X+Iwg0/2B262PSob/kByveLNT7D:XL8BSCgPndQb+NDB6ySC/kByvyNh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_fede8fbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fede8fbf1f1795ddbd9283c5ad2f74869820759fa49b6adb1113df4e19cca3b6"
    family = "unknown"
    file_name = "ecf4307739ca93f1569ce49377a28b31fe1eb0f44b6950dbaafa1925b24c9752.dll"
    file_type = "exe"
    first_seen = "2026-09-12 03:51:45"
  condition:
    hash.sha256(0, filesize) == "fede8fbf1f1795ddbd9283c5ad2f74869820759fa49b6adb1113df4e19cca3b6"
}
```

### Sample 16: `d56c1631b2f816bd`

| Field | Value |
|---|---|
| SHA-256 | `d56c1631b2f816bd9cac1c74bd640404556bb00c4567830d951c75fb7f70c122` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-12 03:49:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e083507343e1774fa3230f88f93e585` |
| SHA-1 | `81c9f06388aac6f0de9dc194815bdc4aa4b2ca3a` |
| SHA-256 | `d56c1631b2f816bd9cac1c74bd640404556bb00c4567830d951c75fb7f70c122` |
| SHA3-384 | `1da6ba6cb7d3b34ccbb8086c77812a42e4466f3943e58e544bb62d34cca5ae044be1d2986782dda0d07b9dfe123af610` |
| TLSH | `T1CCC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:/8vCB+25j6es8RVy9FYpMSUpi+20qUpi+20YQX:/8l25Jyd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_d56c1631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d56c1631b2f816bd9cac1c74bd640404556bb00c4567830d951c75fb7f70c122"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 03:49:33"
  condition:
    hash.sha256(0, filesize) == "d56c1631b2f816bd9cac1c74bd640404556bb00c4567830d951c75fb7f70c122"
}
```

### Sample 17: `79624d5fbbc9dbca`

| Field | Value |
|---|---|
| SHA-256 | `79624d5fbbc9dbca866a3971b801eba6f99450b5340bf434fcd6d182dfe8a479` |
| Family label | `unknown` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-09-12 03:35:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88a8b781558dbdf222263fb69f278433` |
| SHA-1 | `85f6b0e75895fc7f4665b9d3daee0fffa51f59cf` |
| SHA-256 | `79624d5fbbc9dbca866a3971b801eba6f99450b5340bf434fcd6d182dfe8a479` |
| SHA3-384 | `5d5d20a115218a1febdbb5250051234b7c44da796590ee4330f3365753d783a3b6c23175578c77ca2e5aaf98ab5c4410` |
| TLSH | `T13EB302445BE2AAF4CAAF42B892D3DF643300E909749B6E5684180D0CADFF83C5FB1E05` |
| SSDEEP | `3072:4pzaf+TwDIgp4F7Tsz+8M73pJ0AMzYbIOlZOf/:49amTwkh7Ta+80MmFbOf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_79624d5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79624d5fbbc9dbca866a3971b801eba6f99450b5340bf434fcd6d182dfe8a479"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-09-12 03:35:37"
  condition:
    hash.sha256(0, filesize) == "79624d5fbbc9dbca866a3971b801eba6f99450b5340bf434fcd6d182dfe8a479"
}
```

### Sample 18: `bdd4b1198ebbfc96`

| Field | Value |
|---|---|
| SHA-256 | `bdd4b1198ebbfc963373747ee0bf6d0141e0601545c88fff80a9aa1300a8e867` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 03:34:22` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0192e5e0b80fe45603cf8ebfc6582771` |
| SHA-256 | `bdd4b1198ebbfc963373747ee0bf6d0141e0601545c88fff80a9aa1300a8e867` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_bdd4b119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdd4b1198ebbfc963373747ee0bf6d0141e0601545c88fff80a9aa1300a8e867"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 03:34:22"
  condition:
    hash.sha256(0, filesize) == "bdd4b1198ebbfc963373747ee0bf6d0141e0601545c88fff80a9aa1300a8e867"
}
```

### Sample 19: `5b00c60a45f81997`

| Field | Value |
|---|---|
| SHA-256 | `5b00c60a45f81997c20465d87982b3a33cae3c02ecf62240b0f56172782ed5a9` |
| Family label | `unknown` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-09-12 03:33:10` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cd67d876c7e1dfc24f8a044f1985f60` |
| SHA-1 | `42b35ce071e21d9ba1a613a59efa83d7134fef86` |
| SHA-256 | `5b00c60a45f81997c20465d87982b3a33cae3c02ecf62240b0f56172782ed5a9` |
| SHA3-384 | `5eac1aa77b384c27f7ab294a16d2b3dc400689684648301d781250ef8be7bc9327c96aca7522b4b7fa1dcdb0fc5f1c22` |
| TLSH | `T1C4B31238F3E02D25DC781BBAA9B7C3C8BA656508ECA6B6320534185019F497EADE1F54` |
| SSDEEP | `3072:49yg4sYiW28c/9zW3NuY9CkF9H2Iv1+t9:4wg4sYiD/k3N79CW2IM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_5b00c60a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b00c60a45f81997c20465d87982b3a33cae3c02ecf62240b0f56172782ed5a9"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-09-12 03:33:10"
  condition:
    hash.sha256(0, filesize) == "5b00c60a45f81997c20465d87982b3a33cae3c02ecf62240b0f56172782ed5a9"
}
```

### Sample 20: `fd4fe05051826bda`

| Field | Value |
|---|---|
| SHA-256 | `fd4fe05051826bda9353ba88506d2394105c924e7a0aceb6300ddba4fb741e39` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 03:30:31` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4296374979450c21010bee935c34ce7d` |
| SHA-256 | `fd4fe05051826bda9353ba88506d2394105c924e7a0aceb6300ddba4fb741e39` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_fd4fe050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4fe05051826bda9353ba88506d2394105c924e7a0aceb6300ddba4fb741e39"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 03:30:31"
  condition:
    hash.sha256(0, filesize) == "fd4fe05051826bda9353ba88506d2394105c924e7a0aceb6300ddba4fb741e39"
}
```

### Sample 21: `5bdb223a32994f6d`

| Field | Value |
|---|---|
| SHA-256 | `5bdb223a32994f6d309e5050b5c2fc7637f377e01c423e8cfdbfbb053d3b1cba` |
| Family label | `unknown` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-09-12 03:28:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2db61e66ba35d78f2f3a49015d3a3135` |
| SHA-1 | `8c988ff98573e36e6968dfef08cabb1f121928fe` |
| SHA-256 | `5bdb223a32994f6d309e5050b5c2fc7637f377e01c423e8cfdbfbb053d3b1cba` |
| SHA3-384 | `0fb719929cea318692929b69d23b55d2e8142fc11c20c4f12959af4acdd0fbd237e970c3a2a9cc9245598cfd1ada8a93` |
| TLSH | `T1B3D3012663B85E96D426CCBD100F9BB571DF892B4766E371936C8901CF6B8C046C1EE2` |
| SSDEEP | `3072:IG36PYYeoA7iAHIb5sQdKCP3Tl418eu76UJMnzY467LUE:N69q73ysQdjlBeu+SMz36E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_5bdb223a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bdb223a32994f6d309e5050b5c2fc7637f377e01c423e8cfdbfbb053d3b1cba"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-09-12 03:28:15"
  condition:
    hash.sha256(0, filesize) == "5bdb223a32994f6d309e5050b5c2fc7637f377e01c423e8cfdbfbb053d3b1cba"
}
```

### Sample 22: `522e81b62f42b1af`

| Field | Value |
|---|---|
| SHA-256 | `522e81b62f42b1af8caf7ffec9c0e456cbe1c3a8c1c93af48ab5ea7e33fd99fc` |
| Family label | `unknown` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-09-12 03:25:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `296a0c011928e893a7245eb88c333ca5` |
| SHA-1 | `3e307a46f71b72cbd1c4496e400eaee094a22475` |
| SHA-256 | `522e81b62f42b1af8caf7ffec9c0e456cbe1c3a8c1c93af48ab5ea7e33fd99fc` |
| SHA3-384 | `b9398955fe47e23e2d84a04d88dd9bd531fcc7fca8ef9e4828a0488f05213b31331656d569689eac26707567cfe3233c` |
| TLSH | `T13FD3020263F28E1CD978C3769BFB42D51297AA16CFE757308AFB9096245C14CBC2DA19` |
| SSDEEP | `3072:AeZRr6/GA9vhKHNKvnPbYFG9nKwJQAwNspyPRxpx:Aqr6/GA9SIZdJQA4v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_522e81b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "522e81b62f42b1af8caf7ffec9c0e456cbe1c3a8c1c93af48ab5ea7e33fd99fc"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-09-12 03:25:41"
  condition:
    hash.sha256(0, filesize) == "522e81b62f42b1af8caf7ffec9c0e456cbe1c3a8c1c93af48ab5ea7e33fd99fc"
}
```

### Sample 23: `7f2e753ab938a58b`

| Field | Value |
|---|---|
| SHA-256 | `7f2e753ab938a58b8807bd0ef7fb8d42a7de0c0e74012924729093c3a87a4a2e` |
| Family label | `unknown` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-09-12 03:25:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `615bd370d4b896d6fabd72c28957daec` |
| SHA-1 | `6ea7648b607cab02817de85753e62b7393d6d4d6` |
| SHA-256 | `7f2e753ab938a58b8807bd0ef7fb8d42a7de0c0e74012924729093c3a87a4a2e` |
| SHA3-384 | `517bcebfe745ee907c3ce6d925632f284753414628e1b9ed81042a37b24592067adb06bda4f4ac1eecb0cd9d6a3ee33d` |
| TLSH | `T1C5B3024EB6E393ECCC1F09B94403C717BA8ADF8DEF41DA83807145B4A9DA9517E45C19` |
| SSDEEP | `3072:8pGs0Qsoqr1F6y617E1jlNJOBQqAaDk/Tqu0:8Is0QsBrH6yio3NJOABR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_7f2e753a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f2e753ab938a58b8807bd0ef7fb8d42a7de0c0e74012924729093c3a87a4a2e"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-09-12 03:25:40"
  condition:
    hash.sha256(0, filesize) == "7f2e753ab938a58b8807bd0ef7fb8d42a7de0c0e74012924729093c3a87a4a2e"
}
```

### Sample 24: `99ac4893f2aa8767`

| Field | Value |
|---|---|
| SHA-256 | `99ac4893f2aa8767f32701a4cc7d90a3914ae118ce029e59ada6979a7ca83d60` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-12 03:13:12` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d9cbf9eca01f38be7126a75344baebf` |
| SHA-256 | `99ac4893f2aa8767f32701a4cc7d90a3914ae118ce029e59ada6979a7ca83d60` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_99ac4893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ac4893f2aa8767f32701a4cc7d90a3914ae118ce029e59ada6979a7ca83d60"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 03:13:12"
  condition:
    hash.sha256(0, filesize) == "99ac4893f2aa8767f32701a4cc7d90a3914ae118ce029e59ada6979a7ca83d60"
}
```

### Sample 25: `3a1e08b453d00775`

| Field | Value |
|---|---|
| SHA-256 | `3a1e08b453d00775fdba4e4064d9ee3653958d2b64fad3c35e2d0f4ce09fb88c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-12 02:55:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b24a44de3f0342a65c0a645c717e8420` |
| SHA-1 | `9d84b923bbac3e92153a15102fdd473f427d4902` |
| SHA-256 | `3a1e08b453d00775fdba4e4064d9ee3653958d2b64fad3c35e2d0f4ce09fb88c` |
| SHA3-384 | `3f48c4fd2f0713f7ba1066717a14696dfcf28015671f8211e6bd6e104b33d52467468b1b75fb0c7dcfda166dd90efdde` |
| TLSH | `T1D0C28D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11F9CD618B1A` |
| SSDEEP | `768:d8vCB+25j6es8Rr9FYpMSUpi+20qUpi+20YQX:d8l25J9d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_3a1e08b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a1e08b453d00775fdba4e4064d9ee3653958d2b64fad3c35e2d0f4ce09fb88c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 02:55:10"
  condition:
    hash.sha256(0, filesize) == "3a1e08b453d00775fdba4e4064d9ee3653958d2b64fad3c35e2d0f4ce09fb88c"
}
```

### Sample 26: `bdd9063fedf9dcc2`

| Field | Value |
|---|---|
| SHA-256 | `bdd9063fedf9dcc2feecff5bf0123af411301b41d0999ebfd34b012b89027ea7` |
| Family label | `unknown` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-09-12 02:47:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd297c450a7426c7260f8fbba0845bbb` |
| SHA-1 | `fe44d6d70667f35c47e5e54658dacf353113593d` |
| SHA-256 | `bdd9063fedf9dcc2feecff5bf0123af411301b41d0999ebfd34b012b89027ea7` |
| SHA3-384 | `ee403221ac737053ac6859f3738a33a05578a7801f4b1e8fa6fb52888a63d2a5f824529ff2a3ec3adb65b2d5192d63fc` |
| TLSH | `T14DB30213F795FA72C44155B119EB32BBF9BA7D32310B1F07A22A8A3D76B19C422D1C19` |
| SSDEEP | `3072:rg+yoWpoM/XYrz6ccRQr+cycFGqF8T1X:9WZfYyCrTycAqFQZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_bdd9063f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdd9063fedf9dcc2feecff5bf0123af411301b41d0999ebfd34b012b89027ea7"
    family = "unknown"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-09-12 02:47:32"
  condition:
    hash.sha256(0, filesize) == "bdd9063fedf9dcc2feecff5bf0123af411301b41d0999ebfd34b012b89027ea7"
}
```

### Sample 27: `3f3dfec9e1345afd`

| Field | Value |
|---|---|
| SHA-256 | `3f3dfec9e1345afd818fd278d087dcc94be257c82094c981bb2e881c219a3e90` |
| Family label | `unknown` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-09-12 02:46:26` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `129cee22131ca34aa5870d020f69e9b1` |
| SHA-1 | `03f8ded0a0eb71b214eb24ced8a9541ea87da59b` |
| SHA-256 | `3f3dfec9e1345afd818fd278d087dcc94be257c82094c981bb2e881c219a3e90` |
| SHA3-384 | `0c357e82fa6c5a447343775e070d67a2a45a457d2b18e560aa8380e4b44bc1ab4f037e46cb3293f0330ac8d3f966708f` |
| TLSH | `T141B3120473C08671FCA271F8E073D7CCFD05C8AAB61A718744BE49DCD8EA171EA62666` |
| SSDEEP | `1536:8pGih8wHbWosYy4N9aQjLmsSINPwiz938xzcXhTMi1/YQvVBee4RQfG:8pGiqwHSCrx39SuzWwjNHuQfG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_3f3dfec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f3dfec9e1345afd818fd278d087dcc94be257c82094c981bb2e881c219a3e90"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-09-12 02:46:26"
  condition:
    hash.sha256(0, filesize) == "3f3dfec9e1345afd818fd278d087dcc94be257c82094c981bb2e881c219a3e90"
}
```

### Sample 28: `cc511dd392493780`

| Field | Value |
|---|---|
| SHA-256 | `cc511dd39249378019f395fba5a1869dd37d313010b7770f2f279ce0d17dddc7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-12 02:39:00` |
| Reporter | `Bitsight` |
| Tags | `5000, dropped-by-remcos` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f5fa8dbe2bbd7b0f589b94db0edfbe5` |
| SHA-256 | `cc511dd39249378019f395fba5a1869dd37d313010b7770f2f279ce0d17dddc7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_cc511dd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc511dd39249378019f395fba5a1869dd37d313010b7770f2f279ce0d17dddc7"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 02:39:00"
  condition:
    hash.sha256(0, filesize) == "cc511dd39249378019f395fba5a1869dd37d313010b7770f2f279ce0d17dddc7"
}
```

### Sample 29: `7d86501fcd6856ef`

| Field | Value |
|---|---|
| SHA-256 | `7d86501fcd6856efe97f82469500fb2e92f2bc59ceae5aa5589e943550738db9` |
| Family label | `unknown` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-09-12 02:14:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c700a70b3fc11aa902caeff4722e77ef` |
| SHA-1 | `3d7dacb01f5c4378d782f344124f48a7a3f161eb` |
| SHA-256 | `7d86501fcd6856efe97f82469500fb2e92f2bc59ceae5aa5589e943550738db9` |
| SHA3-384 | `49eb54a9ff4c763cef747157563c3bc3bd8ba2965761db6fc21130fa5cff30c38be229e55ea614f94209be864f8e3d91` |
| TLSH | `T1DE040115FFB4CA91D8234F75E86B0E0925D725330961A18DB873A707F8A47749323BAE` |
| SSDEEP | `3072:92rLGwACR4WnvnZdYFEHjHVuvplwJL6PNM+b3ekN5WcTP:iGwA+HYEjHVupeJL6P++6kTB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_7d86501f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d86501fcd6856efe97f82469500fb2e92f2bc59ceae5aa5589e943550738db9"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-09-12 02:14:28"
  condition:
    hash.sha256(0, filesize) == "7d86501fcd6856efe97f82469500fb2e92f2bc59ceae5aa5589e943550738db9"
}
```

### Sample 30: `8b1399615679c18f`

| Field | Value |
|---|---|
| SHA-256 | `8b1399615679c18fdd9bf4cf9f90ad4929e4b3fd69af2991f12a8d304afa2c00` |
| Family label | `unknown` |
| File name | `Request for Quote PR No 164.js` |
| File type | `js` |
| First seen | `2026-09-12 01:47:13` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9703ad0bfe9674227810fa0d50c7873` |
| SHA-1 | `ae737a6e1b22fece29fe6ee3f4e8d7757e563f20` |
| SHA-256 | `8b1399615679c18fdd9bf4cf9f90ad4929e4b3fd69af2991f12a8d304afa2c00` |
| SHA3-384 | `25068b3071b7eabc33f4069b05da77e764a47d0736443d419bc5add670d85aabce2b14f6909065f6163b27bbe4ca6129` |
| TLSH | `T17545001EB939B1588CCA3126623963B1C44B5EBF23375BCB2C10FF95A542CB59CA2717` |
| SSDEEP | `12288:ozythe5yttttlKnoH+Kd28Dz7ye+t8Jv8rr/F//at+jexIz66N5sGr52BttN5nUt:inoZxHye+prR//at+qi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_8b139961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b1399615679c18fdd9bf4cf9f90ad4929e4b3fd69af2991f12a8d304afa2c00"
    family = "unknown"
    file_name = "Request for Quote PR No 164.js"
    file_type = "js"
    first_seen = "2026-09-12 01:47:13"
  condition:
    hash.sha256(0, filesize) == "8b1399615679c18fdd9bf4cf9f90ad4929e4b3fd69af2991f12a8d304afa2c00"
}
```

### Sample 31: `611452d6c49d83db`

| Field | Value |
|---|---|
| SHA-256 | `611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103` |
| Family label | `unknown` |
| File name | `611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103.bin` |
| File type | `exe` |
| First seen | `2026-09-12 01:25:19` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed923eb721e5ef99f094a64b361baabf` |
| SHA-1 | `c769c2e086f46ca68a6affd1bd5a05394d42f5d1` |
| SHA-256 | `611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103` |
| SHA3-384 | `3f329dcd92135a35d1d575ca1e76cf4ed32c4899dfecabae772ba7c53ffe98dbd1eb48c69946744deb329f9b63b2ce1e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17B068D07ACD159E6C09AA33089726551BB74FC441F322BDB2EA0B7782F76BC15E39748` |
| SSDEEP | `49152:btA3ryavDDasVoBM+f1QaF7517IFR2ut/LUPYbHisXLiW1m:btCJUlQEHID2ut/YAHLix` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_611452d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103"
    family = "unknown"
    file_name = "611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103.bin"
    file_type = "exe"
    first_seen = "2026-09-12 01:25:19"
  condition:
    hash.sha256(0, filesize) == "611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103"
}
```

### Sample 32: `202d6cbb3d1c1f63`

| Field | Value |
|---|---|
| SHA-256 | `202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c` |
| Family label | `unknown` |
| File name | `202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c.bin` |
| File type | `exe` |
| First seen | `2026-09-12 01:25:16` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45bb36c5efe2113d0ab3c72440c5c0b1` |
| SHA-1 | `8a4635c218eb497e220ca3c4f6e98aa477143cc2` |
| SHA-256 | `202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c` |
| SHA3-384 | `3ed914ff9bfedcb535fece898576cad17c23becce454a2fa0b2cc9f5440a20f69f341e5e6f4e4bc6b6881e26428c5d80` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1FB367B17AE9188F6C1A9E335C8B74245BA64BC0D873123D32E61BE782F723D16E35B54` |
| SSDEEP | `49152:s/VH67UzaIQ5p/kwzcD4tv4lsJ8naSgcJULPxIf8KA7RkA:sBKV2JMZIf5A` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_202d6cbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c"
    family = "unknown"
    file_name = "202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c.bin"
    file_type = "exe"
    first_seen = "2026-09-12 01:25:16"
  condition:
    hash.sha256(0, filesize) == "202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c"
}
```

### Sample 33: `999ceeda77c4552a`

| Field | Value |
|---|---|
| SHA-256 | `999ceeda77c4552adb04e486f8771daea56a99e9642e1e4510b7e985a3684d89` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-12 00:10:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `796c0797ed02663b15a3b6876e35bcd7` |
| SHA-1 | `53da07a6f517a331a493841d7dc616e3453e9fbf` |
| SHA-256 | `999ceeda77c4552adb04e486f8771daea56a99e9642e1e4510b7e985a3684d89` |
| SHA3-384 | `bc5a9307bd910bfca3b9c5029ac3ea1aa0ed7bf3709160e5ad63ee46c2997441a790cf6ca58dbfda170b7ee86336af0c` |
| TLSH | `T1AD261A97B8924983C4E42676B8BE80C433635EFA9B9B53576D04FE3C3ABE1990D35704` |
| TELFHASH | `t105d0a903df28b7ccd3e9a108a10c091085f43ef20220ae112eca2cef1d12c9230e2812` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:mRTKdzf1DJUdVSYeBBF3kwmfaVtl6TFq3U+LzYnLVYC+a+Fb1esSUzr9prsuuk5S:mWtO+7bdr6VUQlV4HWgNkaZJgRf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_999ceeda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "999ceeda77c4552adb04e486f8771daea56a99e9642e1e4510b7e985a3684d89"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-12 00:10:25"
  condition:
    hash.sha256(0, filesize) == "999ceeda77c4552adb04e486f8771daea56a99e9642e1e4510b7e985a3684d89"
}
```

### Sample 34: `dbb1e585efe9bb66`

| Field | Value |
|---|---|
| SHA-256 | `dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c` |
| Family label | `unknown` |
| File name | `dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c.bin` |
| File type | `elf` |
| First seen | `2026-09-12 00:08:29` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eda1b439fe0ce2d52d15b747894c9563` |
| SHA-1 | `a37d8d3ab22f615f0a7c35d910bc1a340f777921` |
| SHA-256 | `dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c` |
| SHA3-384 | `6d1ccb3932ad8f566cf7b8c3bc2817e14375f03ed6ef9abeb6101e24f1be96580d5faf7f680739b0647ab5b91395018f` |
| TLSH | `T1AD25D665FC828B668AC05ABEFB1DC2DC371317B9C2ED3005561487347BEB99A0E3B552` |
| SSDEEP | `12288:dQUdY0KAof3ADoH7TcSgYgh2UHFVB89/k6hLKsLtaGKSNRh4Z+kk3OINsZXxFO9s:uUwfADb9v7BgCZHk+IepWYmYG9I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_dbb1e585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c"
    family = "unknown"
    file_name = "dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c.bin"
    file_type = "elf"
    first_seen = "2026-09-12 00:08:29"
  condition:
    hash.sha256(0, filesize) == "dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c"
}
```

### Sample 35: `00191bd7f825efda`

| Field | Value |
|---|---|
| SHA-256 | `00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9` |
| Family label | `unknown` |
| File name | `00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9.bin` |
| File type | `unknown` |
| First seen | `2026-09-12 00:08:11` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba2784b2fa0b9581b1fea63f39f6b837` |
| SHA-256 | `00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_00191bd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9"
    family = "unknown"
    file_name = "00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9.bin"
    file_type = "unknown"
    first_seen = "2026-09-12 00:08:11"
  condition:
    hash.sha256(0, filesize) == "00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9"
}
```

### Sample 36: `28e5195b66174575`

| Field | Value |
|---|---|
| SHA-256 | `28e5195b66174575e878e4f48132ef8589a22d8cc8533229f15ea1f96de2ce2a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 23:46:32` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `969c97946b1e4d60ba2015c2bc982929` |
| SHA-1 | `b40cb88999ebb06d25d01875ece563d769aff284` |
| SHA-256 | `28e5195b66174575e878e4f48132ef8589a22d8cc8533229f15ea1f96de2ce2a` |
| SHA3-384 | `db4a3d43b5cf731235d4de848c54eafd195a55671ac47129126f63b263e60d2375a31867f5358e9facffde5958f9a081` |
| IMPHASH | `469bb8b453da3c3ebe870d534557f016` |
| TLSH | `T18AC5226D41941A31F4F30078F18E2396D356344AA3E98C1E37E144C627E7D9BB9CAB6B` |
| SSDEEP | `49152:O33WREeA1ZdmWVRIb+KvEQHebSB7jOP3/j93EgVZ7/IS6CtwfV7X:G3WREZZbRjT67j4vZU2ZI7CefV7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_28e5195b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28e5195b66174575e878e4f48132ef8589a22d8cc8533229f15ea1f96de2ce2a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 23:46:32"
  condition:
    hash.sha256(0, filesize) == "28e5195b66174575e878e4f48132ef8589a22d8cc8533229f15ea1f96de2ce2a"
}
```

### Sample 37: `2324697b8f4009e6`

| Field | Value |
|---|---|
| SHA-256 | `2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9` |
| Family label | `ConnectWise` |
| File name | `2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9.msi` |
| File type | `msi` |
| First seen | `2026-09-11 23:25:15` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e142150275e8ea9e7549a8cce7033997` |
| SHA-1 | `370932163a1e745fb3ee4d199e7a2585016e80e3` |
| SHA-256 | `2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9` |
| SHA3-384 | `bc66abf69029b3037bd44d0a8e03260941991398584885a850226a126a05ecb8b6b49189dbc10f6fecb4f66cac04e0c3` |
| TLSH | `T1EED623116BF89278F1F22A35E876A0B1A5377C515E22D12E2324791E2C75EC0C9B3777` |
| SSDEEP | `196608:HHxcp9ym3nltDUJVsHxcp9ym3ZHxcp9ym3fHxcp9ym30Hxcp9ym3dHxcp9ym37HP:xGplpXGprGppGpSGpPGpFGpY` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_037_2324697b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9"
    family = "ConnectWise"
    file_name = "2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9.msi"
    file_type = "msi"
    first_seen = "2026-09-11 23:25:15"
  condition:
    hash.sha256(0, filesize) == "2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9"
}
```

### Sample 38: `7ef0267249971de2`

| Field | Value |
|---|---|
| SHA-256 | `7ef0267249971de2a5664d4667130f912ed4880fa399a587bba2c23fe87fba2c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 23:13:19` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX9.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60dab9d69a5d3368c98c79ff80f45183` |
| SHA-1 | `5aca735cbf8f1af3d75e88d2aa7d07dbe754e6ca` |
| SHA-256 | `7ef0267249971de2a5664d4667130f912ed4880fa399a587bba2c23fe87fba2c` |
| SHA3-384 | `6efee7d54c11483035fbea121957785b80a345248e57be87da43b2ad2ebd37e148c418d139b3a94c6e48f4f3e023b697` |
| IMPHASH | `469bb8b453da3c3ebe870d534557f016` |
| TLSH | `T16B8533D2C6602A71F6E32178F6260AA2A46D354EB7E082D73310C02E4D937DEFE75657` |
| SSDEEP | `49152:233WREeA1ZdmWVRIb+KvEQHebSB7jOP3/j9:+3WREZZbRjT67j4vZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_7ef02672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ef0267249971de2a5664d4667130f912ed4880fa399a587bba2c23fe87fba2c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 23:13:19"
  condition:
    hash.sha256(0, filesize) == "7ef0267249971de2a5664d4667130f912ed4880fa399a587bba2c23fe87fba2c"
}
```

### Sample 39: `d6bdad8b255a82c2`

| Field | Value |
|---|---|
| SHA-256 | `d6bdad8b255a82c22b6b94b818f2a044a33edff0d52224bb79cfad1faf700c0e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 23:13:10` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX1.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9f5cfc3a20b87ea7c273ccf2d9c394c` |
| SHA-1 | `5d1c08d041f20ea87523364565f8606b6ada2b2f` |
| SHA-256 | `d6bdad8b255a82c22b6b94b818f2a044a33edff0d52224bb79cfad1faf700c0e` |
| SHA3-384 | `9d06408197634fb9a3d8320550a1a0ee25fe0c0a195c4787c142219e8376244ce454e552ed2ef813f80573b9aedb1a59` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T1DA771256E2FD00E8D5BAC0BCC6575517EBB23459173097EB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:/uMLCKXoeOvHiwB3sn+h1h425F+wX0ff6yajCs6+4S3NftN:/5BoeeCwDrh4G+tf6fj4ulN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_d6bdad8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6bdad8b255a82c22b6b94b818f2a044a33edff0d52224bb79cfad1faf700c0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 23:13:10"
  condition:
    hash.sha256(0, filesize) == "d6bdad8b255a82c22b6b94b818f2a044a33edff0d52224bb79cfad1faf700c0e"
}
```

### Sample 40: `f75119b46828e699`

| Field | Value |
|---|---|
| SHA-256 | `f75119b46828e699a35b12230d66f34ce0bd9fe0e79edc9317912e2446ebbff4` |
| Family label | `unknown` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-09-11 23:07:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ff1835b40e866f0597aa4bcc6fcb0da` |
| SHA-1 | `607e51802891a39371da887e512c0d62e1d8479a` |
| SHA-256 | `f75119b46828e699a35b12230d66f34ce0bd9fe0e79edc9317912e2446ebbff4` |
| SHA3-384 | `e884048123b3f9e6d998cad525624d0375a0dcf4a6f27125ba512088fd56bd360a9555dc3ac2b4de2be3f595c9ce2771` |
| TLSH | `T12AA3F1139700F5F6D05DF2706E6B9ECB1E37FC0158B26B29C71BAF6E3E626011501AA2` |
| TELFHASH | `t1d6c0129213103ce223070c017221d1aace020873ba213a2d33398cf8aa20b058901010` |
| SSDEEP | `1536:PnF8/fICOP6MfpPkVpzDhFD0ypScnZAx5heTOdhu6xEHOOGUwiFWZh+DOVrB4:PnkSP9x8rXzD1ZAReqdrWVwi8m84` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_f75119b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75119b46828e699a35b12230d66f34ce0bd9fe0e79edc9317912e2446ebbff4"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-09-11 23:07:15"
  condition:
    hash.sha256(0, filesize) == "f75119b46828e699a35b12230d66f34ce0bd9fe0e79edc9317912e2446ebbff4"
}
```

### Sample 41: `8ab302b2e0fa8735`

| Field | Value |
|---|---|
| SHA-256 | `8ab302b2e0fa873555d95673939b59ca2d4293b6fea338b6c074472cd1ca2333` |
| Family label | `Mirai` |
| File name | `bot.sh4` |
| File type | `elf` |
| First seen | `2026-09-11 23:04:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fc03490ee006010e27e27d70d1a0647` |
| SHA-1 | `a00a0ea090364f1f1be68c0ed9bbda92d700668e` |
| SHA-256 | `8ab302b2e0fa873555d95673939b59ca2d4293b6fea338b6c074472cd1ca2333` |
| SHA3-384 | `3c36a60219021aa322f199b35fec66e4918c74fed7a5260ab12b202ba0d5ada4b8a8ace479bae0cd18dd63d251d4f312` |
| TLSH | `T1B215AE91D2B0E7DDD118DAB42179F9384F12B63332837185F2AF856312AB194B9EDB70` |
| SSDEEP | `12288:DP3yDU7mH2m3ffTEPPqonsdKgdI3bl7er2PdbFTV0hdO1zmP1VqNfhAQp9ywa9nE:8pT3f+ngKCI3lVP27OTkh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_8ab302b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ab302b2e0fa873555d95673939b59ca2d4293b6fea338b6c074472cd1ca2333"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-09-11 23:04:38"
  condition:
    hash.sha256(0, filesize) == "8ab302b2e0fa873555d95673939b59ca2d4293b6fea338b6c074472cd1ca2333"
}
```

### Sample 42: `041bf99578bc1c36`

| Field | Value |
|---|---|
| SHA-256 | `041bf99578bc1c3679f0fac99eeff3ed0eee3913ba462b21e1accd1d07106839` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-11 22:58:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0392ace578d4b2299ee8656dd19f707d` |
| SHA-1 | `1e2609f224e5f64230fd8e70f840b78baa493e68` |
| SHA-256 | `041bf99578bc1c3679f0fac99eeff3ed0eee3913ba462b21e1accd1d07106839` |
| SHA3-384 | `d1a7d278d832b109746ba22a721d1467852a3a6b63941618b197d83de11a506c2d8d6fe2f6f985cf9449cd124f2f2e2c` |
| TLSH | `T16EC28E966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D4B3C719C11FACD618B1A` |
| SSDEEP | `768:5d8vCB+25j6es8RN9FYpMSUpi+20qUpi+20YQX:5d8l25J7d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_041bf995
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "041bf99578bc1c3679f0fac99eeff3ed0eee3913ba462b21e1accd1d07106839"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:58:24"
  condition:
    hash.sha256(0, filesize) == "041bf99578bc1c3679f0fac99eeff3ed0eee3913ba462b21e1accd1d07106839"
}
```

### Sample 43: `26a618a76ddc7827`

| Field | Value |
|---|---|
| SHA-256 | `26a618a76ddc78275deeeda1f76c77c8311a3027aaf54b0dd954c046c2347ad9` |
| Family label | `unknown` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-09-11 22:50:16` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3a96b242608aad52c07f2ef4a29ee0a` |
| SHA-1 | `50c67836ed0262d6edb64039d944fbeed232e10d` |
| SHA-256 | `26a618a76ddc78275deeeda1f76c77c8311a3027aaf54b0dd954c046c2347ad9` |
| SHA3-384 | `15fc09526074353c82dec8c44e6028438bca49a955778339a2d82ac8128f730584a657925a754df339b6a4b55e1ea901` |
| TLSH | `T1C693015615D25AA1DCF827B3C092C30361E1CD8EB547E312928E9F6C89DE4BB58B5B23` |
| SSDEEP | `1536:8phhmi3odyCI6jeCjZMIguTEr9s4VZn5OWnycfLT/p75Zlv8iZU4Sbv+Mw:8ph4mCyH6aAbEr9s+Hny8HRdhZi+X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_26a618a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a618a76ddc78275deeeda1f76c77c8311a3027aaf54b0dd954c046c2347ad9"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-09-11 22:50:16"
  condition:
    hash.sha256(0, filesize) == "26a618a76ddc78275deeeda1f76c77c8311a3027aaf54b0dd954c046c2347ad9"
}
```

### Sample 44: `377379c652f12ac3`

| Field | Value |
|---|---|
| SHA-256 | `377379c652f12ac35cbdbcbd670049127d975fa53968403c1c71b829320f5415` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 22:49:08` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5400386c81f3653735deb3e41f0ce8d9` |
| SHA-256 | `377379c652f12ac35cbdbcbd670049127d975fa53968403c1c71b829320f5415` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_377379c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "377379c652f12ac35cbdbcbd670049127d975fa53968403c1c71b829320f5415"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 22:49:08"
  condition:
    hash.sha256(0, filesize) == "377379c652f12ac35cbdbcbd670049127d975fa53968403c1c71b829320f5415"
}
```

### Sample 45: `42e9c10c1da5c624`

| Field | Value |
|---|---|
| SHA-256 | `42e9c10c1da5c624010da51c0654bfe027e71d175ac7bfcb695608cf01a8a6ca` |
| Family label | `SimpleHelp` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 22:39:51` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, signed, SimpleHelp` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd944e273188b95150be59f249e896be` |
| SHA-1 | `95b5b10a5734c1240b1d4384fc0c2d1984a14ab3` |
| SHA-256 | `42e9c10c1da5c624010da51c0654bfe027e71d175ac7bfcb695608cf01a8a6ca` |
| SHA3-384 | `ecf8877b21e0fc5ee601973b4c004b295ab113141dea6cd1ef12aed32065e7b7d7e713bc5720743b01023e5bc342b323` |
| IMPHASH | `2bf1fc659e1e270e26d98d8a21b8f037` |
| TLSH | `T182762378E6E10DBECE37A5FCD08E40D7A65BB9E203C5016727F085E18E653D0942EE69` |
| SSDEEP | `98304:oxxm7LcLC/7rTM9n8fl/tIi5A/K83k3fYChTkxAPljwl5ShlnAb3u7QL:+YLcLSTM90tFYk3XPljwlIhmXL` |
| ICON-DHASH | `70fcb0b0b0b0f87c` |

#### Technical Assessment

- The sample is tracked as `SimpleHelp` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SimpleHelp_045_42e9c10c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42e9c10c1da5c624010da51c0654bfe027e71d175ac7bfcb695608cf01a8a6ca"
    family = "SimpleHelp"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 22:39:51"
  condition:
    hash.sha256(0, filesize) == "42e9c10c1da5c624010da51c0654bfe027e71d175ac7bfcb695608cf01a8a6ca"
}
```

### Sample 46: `872084e1b23f76e7`

| Field | Value |
|---|---|
| SHA-256 | `872084e1b23f76e71344d173ba0db5a74937e47be5fa1300c63b95ddac532962` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 22:33:13` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84622e10e855d1ee4d43b6018a2f7274` |
| SHA-256 | `872084e1b23f76e71344d173ba0db5a74937e47be5fa1300c63b95ddac532962` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_872084e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872084e1b23f76e71344d173ba0db5a74937e47be5fa1300c63b95ddac532962"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 22:33:13"
  condition:
    hash.sha256(0, filesize) == "872084e1b23f76e71344d173ba0db5a74937e47be5fa1300c63b95ddac532962"
}
```

### Sample 47: `3102c7b291c9c10c`

| Field | Value |
|---|---|
| SHA-256 | `3102c7b291c9c10cda2e3e7901fb66940a98bb75ca0d728a694787db57b76b39` |
| Family label | `unknown` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-09-11 22:32:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47c862a61d77e18030ffaa7c20d333ad` |
| SHA-1 | `a86e9333f0e83d13f962deb9837c18c79b842a8a` |
| SHA-256 | `3102c7b291c9c10cda2e3e7901fb66940a98bb75ca0d728a694787db57b76b39` |
| SHA3-384 | `cf56f69468494947851e52ae0f258833e35cc7b3e22a8eeaf4e2608652660668645052357eab71cc10f78190e0e83170` |
| TLSH | `T1C1F30217EFC4AC14C8729672CCBF176807C74C429AE1918B9453BB677124B3EA20B97E` |
| SSDEEP | `3072:k279Q9FmLgiRhuViL0m11BknchOQT2MoQ0rI:nQ9FmkAmmTB+yTMX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_3102c7b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3102c7b291c9c10cda2e3e7901fb66940a98bb75ca0d728a694787db57b76b39"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-09-11 22:32:06"
  condition:
    hash.sha256(0, filesize) == "3102c7b291c9c10cda2e3e7901fb66940a98bb75ca0d728a694787db57b76b39"
}
```

### Sample 48: `0f30e22204e82249`

| Field | Value |
|---|---|
| SHA-256 | `0f30e22204e82249862c49a460537062d2e6a86251e5ba7c8c76d2751310c0d2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 22:20:26` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac4e9fb3ddeac8f7661937c873ab869a` |
| SHA-1 | `e75c297a1401b3bc11678cfff318566ef543c42c` |
| SHA-256 | `0f30e22204e82249862c49a460537062d2e6a86251e5ba7c8c76d2751310c0d2` |
| SHA3-384 | `95c1852d7fdad58b70a09bdc9e468cab17aa774f619393c027b11d4997d39f18192ee2010a73ac0ecb03900450ecfd49` |
| IMPHASH | `1b391fc77bb90cff1c2e8bacbd2b5b38` |
| TLSH | `T14517338952003295EFA3A23BD6ABD946DE3238362715C8DB897493577E232D08D3DF53` |
| SSDEEP | `393216:X85vzasFl7dCR1C99fdJNsCq7rAGuOWCEDMJ83a10LQXdwWws84xPtOnklB:M5vzJFlUR1OXNsCqFupCEDOEaWQtwjB2` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_0f30e222
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f30e22204e82249862c49a460537062d2e6a86251e5ba7c8c76d2751310c0d2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 22:20:26"
  condition:
    hash.sha256(0, filesize) == "0f30e22204e82249862c49a460537062d2e6a86251e5ba7c8c76d2751310c0d2"
}
```

### Sample 49: `289eba021664d56c`

| Field | Value |
|---|---|
| SHA-256 | `289eba021664d56c712b0fe24c3405101648fc158a35073e8e167a048cf9ba34` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-09-11 22:19:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0834e576c4445f5190f25be4e50d145` |
| SHA-1 | `ecac53b726d73e4dab6c4b7876f7d419050731cc` |
| SHA-256 | `289eba021664d56c712b0fe24c3405101648fc158a35073e8e167a048cf9ba34` |
| SHA3-384 | `b76ff382b3eda6ec138da8e5d2463a88212fe371a9c929040003e568e2b06f47eec25539dc833527cefb9b0b2293b195` |
| TLSH | `T1C0456C466372CF8CF354E67001B39A169EA611B316E361C6A2BDE620376125C1DAFFF4` |
| TELFHASH | `t18861c0a8097817e4b3651c8d4aedff3695a320ef3a161d339e10e86ee726a835d10c1d` |
| SSDEEP | `24576:B9EG9yj/osKOxS+qp7PuBy4fVGQucXNPQlbogx6qW:cisFqFP54fJuc9we` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_289eba02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "289eba021664d56c712b0fe24c3405101648fc158a35073e8e167a048cf9ba34"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-11 22:19:42"
  condition:
    hash.sha256(0, filesize) == "289eba021664d56c712b0fe24c3405101648fc158a35073e8e167a048cf9ba34"
}
```

### Sample 50: `7e1ae53631f43638`

| Field | Value |
|---|---|
| SHA-256 | `7e1ae53631f43638bbfe0596aa871163b1cb0227f2ff49628b460082ff9e318a` |
| Family label | `Mirai` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-09-11 22:18:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `096585cdadb9d83b5ce43baed8a75621` |
| SHA-1 | `84f507a3ac7dcc69113f45d528e92bfe4ed6aeb1` |
| SHA-256 | `7e1ae53631f43638bbfe0596aa871163b1cb0227f2ff49628b460082ff9e318a` |
| SHA3-384 | `5920c8ecf9be03142a7dbc59db14ac11a26414697c91e1bc9d4c474dc90282fff206c89b29c4ad67f7b777b386874d07` |
| TLSH | `T115457C05DFA01FDFD0AFCE30462E970B08ED89A712C7B77561BC8859B39A2494ED7858` |
| SSDEEP | `12288:QOaJ2HqLmiOkcHL01rnuMzRnKvzXt7gOgXVVXx6Z1Hct/D2enMZnd7Psbtut6DIc:QU7mcTcjziUyfS85OECQyu2h3X4RlMY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_7e1ae536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1ae53631f43638bbfe0596aa871163b1cb0227f2ff49628b460082ff9e318a"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-11 22:18:30"
  condition:
    hash.sha256(0, filesize) == "7e1ae53631f43638bbfe0596aa871163b1cb0227f2ff49628b460082ff9e318a"
}
```

### Sample 51: `2b162afcac93c852`

| Field | Value |
|---|---|
| SHA-256 | `2b162afcac93c8522f3ea60ce95b8f00eef7572e6a26e9bc66e9d37314b2c07b` |
| Family label | `unknown` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-09-11 22:16:16` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `617c861e5b2e54b5c1d86ef041074f4a` |
| SHA-1 | `699995bc5cc50b21864adc2de55eab06c59f0ec4` |
| SHA-256 | `2b162afcac93c8522f3ea60ce95b8f00eef7572e6a26e9bc66e9d37314b2c07b` |
| SHA3-384 | `8b8992a137031da7a3ce28d82ddd4317aa6f8b1df00f28804eb1ff5ca814fed649eb954881572ca67254d93428bdcad5` |
| TLSH | `T1E993010877E6268BCD2A1CB740ABE7C57B46D99FF2A07F03458814219D9BBB26CC103D` |
| SSDEEP | `1536:8pGMhYXwLgUWlKSJSg4q70yIKZ0z7b6uVf7fLF+WpZFBDWIAVTceD:8pGMuALgUKJ0qWKZu7emrAgZFoIAqeD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_2b162afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b162afcac93c8522f3ea60ce95b8f00eef7572e6a26e9bc66e9d37314b2c07b"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-09-11 22:16:16"
  condition:
    hash.sha256(0, filesize) == "2b162afcac93c8522f3ea60ce95b8f00eef7572e6a26e9bc66e9d37314b2c07b"
}
```

### Sample 52: `8ddb90d70c6eb79c`

| Field | Value |
|---|---|
| SHA-256 | `8ddb90d70c6eb79c031f14c269cbc26a9c0b9733b97d37dc816935fbc195b68c` |
| Family label | `unknown` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-09-11 22:13:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ef2ebe611ed7ab62027906aceb4bd7b` |
| SHA-1 | `28edf6ce07db20f51b1ed200d62e28fb461484ec` |
| SHA-256 | `8ddb90d70c6eb79c031f14c269cbc26a9c0b9733b97d37dc816935fbc195b68c` |
| SHA3-384 | `b9401397c56403a9378e452bc94cf5b49b898bb89f5ad098b691684adc9d3b739cc4cd5a4a35761461002934eaddd42c` |
| TLSH | `T165C3021B6FF4AFC7C00C9C7A049C577631AE8BA61BA6D763D23C8541BC816E4A391CB5` |
| SSDEEP | `3072:SGYKdiBHJyCe02zdMoDReglfpJJ/UVivASEK8:IKgsCMM0Re0UVi4xK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_8ddb90d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddb90d70c6eb79c031f14c269cbc26a9c0b9733b97d37dc816935fbc195b68c"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-09-11 22:13:39"
  condition:
    hash.sha256(0, filesize) == "8ddb90d70c6eb79c031f14c269cbc26a9c0b9733b97d37dc816935fbc195b68c"
}
```

### Sample 53: `075bc80720bfb217`

| Field | Value |
|---|---|
| SHA-256 | `075bc80720bfb2176c2ca8802dd8e3c516b5b7bacc666a57d0c0f05749059867` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-11 22:11:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46ab523c9a3fab0773820c7dec4a88f3` |
| SHA-1 | `8512b5846c71afbe176a4601cca9da72f3fbca40` |
| SHA-256 | `075bc80720bfb2176c2ca8802dd8e3c516b5b7bacc666a57d0c0f05749059867` |
| SHA3-384 | `3408a2e74c2957dd4501f5bd0aaad8cef2578a8a8ebbcea86856800ea63d3df03e7a36f4d10eaca510c188d6b41e47a8` |
| TLSH | `T1E725A08CE96FBDC6F3CAF378970D96A1A52B7170E26360A33547535E82D61D4CAF0920` |
| SSDEEP | `12288:+Q3jJSwgcb6xV/EHdwvahJg/2UWU82Zh62+CezzMTqGPNDAwVysa9aw57PsiYA:l7RuxpE9FoxH82Zh9PefM7FydWT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_075bc807
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "075bc80720bfb2176c2ca8802dd8e3c516b5b7bacc666a57d0c0f05749059867"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-11 22:11:23"
  condition:
    hash.sha256(0, filesize) == "075bc80720bfb2176c2ca8802dd8e3c516b5b7bacc666a57d0c0f05749059867"
}
```

### Sample 54: `8b4664c393c78d5e`

| Field | Value |
|---|---|
| SHA-256 | `8b4664c393c78d5e5cb22b6f95afd9ed70751b56a8593c53aa8626c5116e0783` |
| Family label | `ValleyRAT` |
| File name | `资源_版本_图标_4419.exe` |
| File type | `exe` |
| First seen | `2026-09-11 22:10:21` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bg[qtsc], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb8a2ab4dd693900fcf28a6d28eed368` |
| SHA-1 | `9cc8e5cadd6c82a97a9fc2a5d033fe9d595c6b0c` |
| SHA-256 | `8b4664c393c78d5e5cb22b6f95afd9ed70751b56a8593c53aa8626c5116e0783` |
| SHA3-384 | `645c6214308571d572b95bc693178e4ff476ddbb6f5279663f16c2873bfc8569f3b2f0c41982f3e060f1d6ed76db419e` |
| IMPHASH | `56a3dff4fc79ae899efd9abcc482391c` |
| TLSH | `T141241756EB7255F9C4FEC1388296633ABE317C1D87B5679B8F8087261B62790F939300` |
| SSDEEP | `3072:Vp7LCZHFDk31XstYX67PegpEuSdfDA6+jHcqQji3xxhSH0OhBM+OTNvGg8QlE7wN:VpvctYX67PegplStDA6c8xH/M+pqanlq` |
| ICON-DHASH | `b068f8fe7f3f9e86` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_054_8b4664c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b4664c393c78d5e5cb22b6f95afd9ed70751b56a8593c53aa8626c5116e0783"
    family = "ValleyRAT"
    file_name = "资源_版本_图标_4419.exe"
    file_type = "exe"
    first_seen = "2026-09-11 22:10:21"
  condition:
    hash.sha256(0, filesize) == "8b4664c393c78d5e5cb22b6f95afd9ed70751b56a8593c53aa8626c5116e0783"
}
```

### Sample 55: `d1b852aad9b9f623`

| Field | Value |
|---|---|
| SHA-256 | `d1b852aad9b9f623010dcfe1ab3ee3eb125dc6d9dafcd26e93ac8fe59d13a4fd` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-11 22:10:15` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `182ed9efc4ab43741e06dca05cc1dcf0` |
| SHA-1 | `456a39a0e8655fb90df7fee76008dfbb7a186852` |
| SHA-256 | `d1b852aad9b9f623010dcfe1ab3ee3eb125dc6d9dafcd26e93ac8fe59d13a4fd` |
| SHA3-384 | `916d1e842253a71201ad7b643fdb75e3932eb350bfe79b3dee00b0648f97ff61f0b11bcd4b8277f4f130cd99f94aaa4a` |
| TLSH | `T1E7C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:lA8vCB+25j6es8RM9FYpMSUpi+20qUpi+20YQX:a8l25Jad2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_d1b852aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b852aad9b9f623010dcfe1ab3ee3eb125dc6d9dafcd26e93ac8fe59d13a4fd"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:10:15"
  condition:
    hash.sha256(0, filesize) == "d1b852aad9b9f623010dcfe1ab3ee3eb125dc6d9dafcd26e93ac8fe59d13a4fd"
}
```

### Sample 56: `92d7268dd1d01a36`

| Field | Value |
|---|---|
| SHA-256 | `92d7268dd1d01a365834bfaaee3d2f30f477dd997fdc747a009438a16040d814` |
| Family label | `ValleyRAT` |
| File name | `2026.09.11裁员名单及补偿方案WPS.exe` |
| File type | `exe` |
| First seen | `2026-09-11 22:09:20` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bg[qtsc], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3e78d794ff6446ad9a77d75422262f0` |
| SHA-1 | `90bbd8c24325c229894ccc828596fe75bc6a3743` |
| SHA-256 | `92d7268dd1d01a365834bfaaee3d2f30f477dd997fdc747a009438a16040d814` |
| SHA3-384 | `5a3c5bf2a25b398893c0f2c760fdbc9bad14a3f53dcd8233bf73c1aa6076ddace34c2e61ededbf6386925286fd438ce9` |
| IMPHASH | `0c5cce9f612130159faa258e81fe8db4` |
| TLSH | `T1F3D57D7BE2584ADCC256C879D1420F639570380E0F3662B762D34BA52F62639DFAD378` |
| SSDEEP | `49152:DNfVVkDIU7pDnHOGfHyluDO6QgABApXwF949QT2Yip6Y/+3bLdg:hNV0OMNGip6/Ng` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_056_92d7268d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92d7268dd1d01a365834bfaaee3d2f30f477dd997fdc747a009438a16040d814"
    family = "ValleyRAT"
    file_name = "2026.09.11裁员名单及补偿方案WPS.exe"
    file_type = "exe"
    first_seen = "2026-09-11 22:09:20"
  condition:
    hash.sha256(0, filesize) == "92d7268dd1d01a365834bfaaee3d2f30f477dd997fdc747a009438a16040d814"
}
```

### Sample 57: `2e8e8593bab13ebc`

| Field | Value |
|---|---|
| SHA-256 | `2e8e8593bab13ebceb50cb1905f1c78d96c8fa5eee3cfb1fef5e8e9cc2d35bba` |
| Family label | `unknown` |
| File name | `2026.09.11....人 员 名 单 LF.exe` |
| File type | `exe` |
| First seen | `2026-09-11 22:07:58` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bg[qtsc], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3afc5ab77b64233b2a5bd347b04eee9f` |
| SHA-1 | `dfb49d2e59bacb312277136d793c5be936ce26a8` |
| SHA-256 | `2e8e8593bab13ebceb50cb1905f1c78d96c8fa5eee3cfb1fef5e8e9cc2d35bba` |
| SHA3-384 | `c94fde618071e965ed958372488471fa8ec14b253f934c32bbf2dd267845d033ec3a8dde9130d72896f183a605dbe722` |
| IMPHASH | `d2030e90db5f4cc9f8268db27befb0dd` |
| TLSH | `T17FF34B0B73A076F8D06FA67488D24751E7B178B55BF2874F1B94422A1F77280AF39722` |
| SSDEEP | `3072:c6FALTxhdy9GveT7iNy2JvjcN8OE8bT6RNfMwdhzCXF/8L+aq/pljigoDJF88:WHKNjTENfJfzW/8LqYJFX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_2e8e8593
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e8e8593bab13ebceb50cb1905f1c78d96c8fa5eee3cfb1fef5e8e9cc2d35bba"
    family = "unknown"
    file_name = "2026.09.11....人 员 名 单 LF.exe"
    file_type = "exe"
    first_seen = "2026-09-11 22:07:58"
  condition:
    hash.sha256(0, filesize) == "2e8e8593bab13ebceb50cb1905f1c78d96c8fa5eee3cfb1fef5e8e9cc2d35bba"
}
```

### Sample 58: `8ecfb2433de0daff`

| Field | Value |
|---|---|
| SHA-256 | `8ecfb2433de0daff367218bcfcc8948208dd638409f84d1a3ebec384ef0954ee` |
| Family label | `Mirai` |
| File name | `bot.ppc` |
| File type | `elf` |
| First seen | `2026-09-11 22:07:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `301303f36cfc9ad6305be44f88375139` |
| SHA-1 | `4b0431b2b4011f25804df46f8c0ea7f7c220184c` |
| SHA-256 | `8ecfb2433de0daff367218bcfcc8948208dd638409f84d1a3ebec384ef0954ee` |
| SHA3-384 | `a5efe2b3c3341555df6588bc80c2e2d540119691575b0891e01d83c893c6765db6f5ab1c03b4c98f0cea1703d0f12a84` |
| TLSH | `T1A5458E06FB2881A3D5465DF0173F57C6F725661310FAA22A330FAB232372A3A95C7795` |
| SSDEEP | `24576:dCtBHe9SUoysbWnuyjXoQzmtxFZqFItrC2t7r/wJi3Pr8V:dGHe9SUoyRuyjHz83qFItC2t/S+Pr2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_8ecfb243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ecfb2433de0daff367218bcfcc8948208dd638409f84d1a3ebec384ef0954ee"
    family = "Mirai"
    file_name = "bot.ppc"
    file_type = "elf"
    first_seen = "2026-09-11 22:07:38"
  condition:
    hash.sha256(0, filesize) == "8ecfb2433de0daff367218bcfcc8948208dd638409f84d1a3ebec384ef0954ee"
}
```

### Sample 59: `006037c0aaf9e993`

| Field | Value |
|---|---|
| SHA-256 | `006037c0aaf9e99318842e41057f4f47092ba8dbbd4f7d24ad0f7684a895ac3f` |
| Family label | `Mirai` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-09-11 22:07:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26c7f9505519c4368fd9c1a79852a3d5` |
| SHA-1 | `261cfa7e002c5cb670e2768058d6cc1be69b3f3e` |
| SHA-256 | `006037c0aaf9e99318842e41057f4f47092ba8dbbd4f7d24ad0f7684a895ac3f` |
| SHA3-384 | `fe5afc3dc993e681945c6e9cd4bc61ba6f8802aa3dab01662f227548f48ffc06cfb088b717e980b95274e25337cc8b9b` |
| TLSH | `T125254B88F5D0EF96C2C4A9B6F31C559C33130735E2EB710699299B3137EB46B0E7AA11` |
| TELFHASH | `t180f0e134798d19f880d55bd6d391863ddc5a14b6c7b13052cf70190fce21fc2746a472` |
| SSDEEP | `24576:VCNXygclO6bTMtXq1rqBbgR0iRc0aUQMc:Vb34qdGFe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_006037c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "006037c0aaf9e99318842e41057f4f47092ba8dbbd4f7d24ad0f7684a895ac3f"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-09-11 22:07:35"
  condition:
    hash.sha256(0, filesize) == "006037c0aaf9e99318842e41057f4f47092ba8dbbd4f7d24ad0f7684a895ac3f"
}
```

### Sample 60: `a9e5cd6b32e7f977`

| Field | Value |
|---|---|
| SHA-256 | `a9e5cd6b32e7f977682e529a669cf991f61764f76cabba258fd1a9391e0cdfed` |
| Family label | `unknown` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-09-11 22:07:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `505b274cb4c794e0f1ddc0fbf1e56c66` |
| SHA-1 | `b0feed547edc1d71a7d1a17bc846c36bdbe0785f` |
| SHA-256 | `a9e5cd6b32e7f977682e529a669cf991f61764f76cabba258fd1a9391e0cdfed` |
| SHA3-384 | `63c3a74fead9e6c9ff36f2cddc139071ec3a37922908321156ec43c819dc404432c7ea3dd2c0f802dfb487dee089c549` |
| TLSH | `T1AD930296A3C28EA2CCA71A34D6D7C795560EF84CF7B9770560387970A8CE07BA8F5530` |
| SSDEEP | `1536:8pGMhfStZ7BoT6iF5QKf5Zf+x8OzRyTsXyykQifZ9cvigBdNU7SFkIm3VknU:8pGMdStZ7emiMKf5YxJR4siHQif/fude` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_a9e5cd6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9e5cd6b32e7f977682e529a669cf991f61764f76cabba258fd1a9391e0cdfed"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-09-11 22:07:34"
  condition:
    hash.sha256(0, filesize) == "a9e5cd6b32e7f977682e529a669cf991f61764f76cabba258fd1a9391e0cdfed"
}
```

### Sample 61: `4b10df23597ecbe7`

| Field | Value |
|---|---|
| SHA-256 | `4b10df23597ecbe7be2e660976db1dc16f6ae8965c87348f09ae94c1b63c5c08` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 22:04:47` |
| Reporter | `Bitsight` |
| Tags | `BB3.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f2012275ce6aa71c108e4f175bdebbd` |
| SHA-1 | `795b39bd17374a6ee957215d3d97533edd4b19b3` |
| SHA-256 | `4b10df23597ecbe7be2e660976db1dc16f6ae8965c87348f09ae94c1b63c5c08` |
| SHA3-384 | `a7b28991a000d28387751752eac151d768cd89b800705c9e67a225e2233593cde133e271ba3865731c73ac6655d53664` |
| IMPHASH | `4c7b612841981cb0d00713551b2da47c` |
| TLSH | `T169F51224EAA041FDF166C274CE87A523F6B2B4491760A9DF03D189B52F372E14B3EB51` |
| SSDEEP | `49152:6clFTcdrfz+SG6F5yEDowjQYe6RmIWtNOdFqM9a2PQA1efgKsualXW8s72X0:UzlysowjQ+IIoNOdFDa2PQorFts7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_4b10df23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b10df23597ecbe7be2e660976db1dc16f6ae8965c87348f09ae94c1b63c5c08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 22:04:47"
  condition:
    hash.sha256(0, filesize) == "4b10df23597ecbe7be2e660976db1dc16f6ae8965c87348f09ae94c1b63c5c08"
}
```

### Sample 62: `a3d81818dff46b43`

| Field | Value |
|---|---|
| SHA-256 | `a3d81818dff46b4308800261c4d762eade3580fe6cfa1b216fb93f4fe6d507da` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 22:03:15` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edff0ec676c8df627510c9f5d3a27d13` |
| SHA-256 | `a3d81818dff46b4308800261c4d762eade3580fe6cfa1b216fb93f4fe6d507da` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_a3d81818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3d81818dff46b4308800261c4d762eade3580fe6cfa1b216fb93f4fe6d507da"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 22:03:15"
  condition:
    hash.sha256(0, filesize) == "a3d81818dff46b4308800261c4d762eade3580fe6cfa1b216fb93f4fe6d507da"
}
```

### Sample 63: `7071105d106dd6e6`

| Field | Value |
|---|---|
| SHA-256 | `7071105d106dd6e6272f56d73d8868b9c025727d099c5d73bb7c56f24ace4cd0` |
| Family label | `unknown` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-09-11 22:03:13` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b04ac548268c3d246bd771298c155ecf` |
| SHA-1 | `a4c56a49198ed33cdccc353715beb01123ea083f` |
| SHA-256 | `7071105d106dd6e6272f56d73d8868b9c025727d099c5d73bb7c56f24ace4cd0` |
| SHA3-384 | `e8c8ad515699e88c78800caf327804bac42ce9f80f16349591f1e7f472be781f864faf87fa71d08dfcf0c5894e070439` |
| TLSH | `T110C3127BBBB34F1AD25CC770C5238794AFA1B97ADD8786298E9AD57CF104AC83105309` |
| SSDEEP | `3072:msA9+hoAg3wP6b/BKXa97EDyQIQQmUi7v2R:mhZAJyDBKFy1F3kvi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_7071105d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7071105d106dd6e6272f56d73d8868b9c025727d099c5d73bb7c56f24ace4cd0"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-09-11 22:03:13"
  condition:
    hash.sha256(0, filesize) == "7071105d106dd6e6272f56d73d8868b9c025727d099c5d73bb7c56f24ace4cd0"
}
```

### Sample 64: `70cd92cc85d2d090`

| Field | Value |
|---|---|
| SHA-256 | `70cd92cc85d2d09088a6e771f56c024112408f8331182176abc01acb1b0d4dab` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-11 22:00:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff124366e7d544ca86a91f4fca324a0a` |
| SHA-1 | `0b513e0c560ae127fa2010178aae2016a0ff3d61` |
| SHA-256 | `70cd92cc85d2d09088a6e771f56c024112408f8331182176abc01acb1b0d4dab` |
| SHA3-384 | `c6ff15d0a7ca8ccda7160c392823adc3b112dada46cbc77d73318188fd00107f9a3d39517a3f9b299832bb67fc055fd9` |
| TLSH | `T15B236D6526857C249A99C4371D7E2F0CBDAD43E6320492EE7FCA3CF28C5A69DD10871D` |
| SSDEEP | `768:dXRWNGxVp9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:nlxEcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_70cd92cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70cd92cc85d2d09088a6e771f56c024112408f8331182176abc01acb1b0d4dab"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:00:46"
  condition:
    hash.sha256(0, filesize) == "70cd92cc85d2d09088a6e771f56c024112408f8331182176abc01acb1b0d4dab"
}
```

### Sample 65: `5d757e786fd27a16`

| Field | Value |
|---|---|
| SHA-256 | `5d757e786fd27a16b5ad72055c510603fed18a91221011e20dbe6959f649af3f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-11 22:00:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f14f340cd47024eb55f50fdab0a76e2a` |
| SHA-1 | `f23414b47e14c455d63a1d2d489d6f7ae4e9bc70` |
| SHA-256 | `5d757e786fd27a16b5ad72055c510603fed18a91221011e20dbe6959f649af3f` |
| SHA3-384 | `f4bb23d5c1147c9e29094f68321d7e18ff6513c5f2a857f468915b53e1fb3ad2a5810479b8cbf7a3484d348c2119151b` |
| TLSH | `T12D235C6516867C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A6ADD10971D` |
| SSDEEP | `768:P+m9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:P+Dcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_5d757e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d757e786fd27a16b5ad72055c510603fed18a91221011e20dbe6959f649af3f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:00:45"
  condition:
    hash.sha256(0, filesize) == "5d757e786fd27a16b5ad72055c510603fed18a91221011e20dbe6959f649af3f"
}
```

### Sample 66: `ae58a420b0c7c35b`

| Field | Value |
|---|---|
| SHA-256 | `ae58a420b0c7c35b5b56ccd413c5e0cf73935b433bc58a30d31634fb4d12fc38` |
| Family label | `Mirai` |
| File name | `bot.i686` |
| File type | `elf` |
| First seen | `2026-09-11 21:59:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ef28a5445b18ee7166931bec608d424` |
| SHA-1 | `f7f440bd56baa2cba5e3cf457f4fa9f61af9e28f` |
| SHA-256 | `ae58a420b0c7c35b5b56ccd413c5e0cf73935b433bc58a30d31634fb4d12fc38` |
| SHA3-384 | `4188b62869158d79ab3e77fbb5e25c93a443daa9ae4161389e6e74801ed7c8152dbdd74aff72253ea7b2262eb99d5572` |
| TLSH | `T1C6456BC8E3E3D1F9F25385B0024FEBA71D7442266053F6E6E78D6A6371733521A5A238` |
| TELFHASH | `t12f228ab329ad58ec6bf049158a9b7520de66e03726f039b20df354d1ab23e435a36474` |
| SSDEEP | `24576:RJ59P9WVhv3h2lCcGjH/CyEATfQYDsIvM9mZ4plLNVd7:Rhyhv3h7NfBTfLwIaHd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_ae58a420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae58a420b0c7c35b5b56ccd413c5e0cf73935b433bc58a30d31634fb4d12fc38"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-09-11 21:59:30"
  condition:
    hash.sha256(0, filesize) == "ae58a420b0c7c35b5b56ccd413c5e0cf73935b433bc58a30d31634fb4d12fc38"
}
```

### Sample 67: `668dcf124501c176`

| Field | Value |
|---|---|
| SHA-256 | `668dcf124501c1767d4ebc19f29cb44d6474cbff28947d63a695628f467b6345` |
| Family label | `Gh0stRAT` |
| File name | `SuggestAssist.exe` |
| File type | `exe` |
| First seen | `2026-09-11 21:57:17` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, Gh0stRAT, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f070ad0d01de3696b7452420a8fdd254` |
| SHA-1 | `ca114fe4812a708cd1d36320703beccc6fb927e2` |
| SHA-256 | `668dcf124501c1767d4ebc19f29cb44d6474cbff28947d63a695628f467b6345` |
| SHA3-384 | `9d4a1f975528e81a129012f7547526c0ac4edd4eb379d7bc7cfa4f5ac660259f5663f72591f2ba9446a5937b909ea520` |
| IMPHASH | `00e7f69a2de2c7b0876b0819346afe25` |
| TLSH | `T1F645E772BF0B817DD7AC143BC664E6AF5F3991D80B92C897C2950F6DE4F31A23529A10` |
| SSDEEP | `24576:TbMEE++DioCzuBXBT0VKGiZ2dKt+QAbdHq:I+cKzLziZ2ItDAbdH` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_067_668dcf12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668dcf124501c1767d4ebc19f29cb44d6474cbff28947d63a695628f467b6345"
    family = "Gh0stRAT"
    file_name = "SuggestAssist.exe"
    file_type = "exe"
    first_seen = "2026-09-11 21:57:17"
  condition:
    hash.sha256(0, filesize) == "668dcf124501c1767d4ebc19f29cb44d6474cbff28947d63a695628f467b6345"
}
```

### Sample 68: `91dfe3049b9de072`

| Field | Value |
|---|---|
| SHA-256 | `91dfe3049b9de072378178064f2a248efa13dcdc23e0b51e578a5f4378e2b827` |
| Family label | `Gh0stRAT` |
| File name | `SuggestAssist.exe` |
| File type | `exe` |
| First seen | `2026-09-11 21:57:17` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, Gh0stRAT, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `832e5ff3482cd9e4fba4e2fe22799cd8` |
| SHA-1 | `7436b37fae21f04841e667cae15d8b6b7d67e7e5` |
| SHA-256 | `91dfe3049b9de072378178064f2a248efa13dcdc23e0b51e578a5f4378e2b827` |
| SHA3-384 | `2d6a08dc490eaa2f3e25ed86c66a31062355d265dec732860ce9c2f0a74ae1c5f4cb16e16e4a118b6f793dac230c076c` |
| IMPHASH | `00e7f69a2de2c7b0876b0819346afe25` |
| TLSH | `T16845E772BF0B817DD7AC143BC664E6AF5F3991D80B92C897C2950F6DE4F31A23529A10` |
| SSDEEP | `24576:8bMEE++DioCzuBXBT0VKGiZ2dKt+QAbdHq:/+cKzLziZ2ItDAbdH` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_068_91dfe304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91dfe3049b9de072378178064f2a248efa13dcdc23e0b51e578a5f4378e2b827"
    family = "Gh0stRAT"
    file_name = "SuggestAssist.exe"
    file_type = "exe"
    first_seen = "2026-09-11 21:57:17"
  condition:
    hash.sha256(0, filesize) == "91dfe3049b9de072378178064f2a248efa13dcdc23e0b51e578a5f4378e2b827"
}
```

### Sample 69: `1bb6d17dfbb9e9f5`

| Field | Value |
|---|---|
| SHA-256 | `1bb6d17dfbb9e9f568643559f62fd66066fcf965199de062552bba2b30c37df0` |
| Family label | `unknown` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-09-11 21:56:27` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47265f445e9bca12003b91826c19e2e8` |
| SHA-1 | `e948ead2dfdde3a71575b50dceeb6da65e0e2c42` |
| SHA-256 | `1bb6d17dfbb9e9f568643559f62fd66066fcf965199de062552bba2b30c37df0` |
| SHA3-384 | `8385641804ec39bfaf7ef490b5c08b1e305269b3756efc58c2c3af4db2ec03cb1572c6d10ac63e4df9881658082d5bbc` |
| TLSH | `T196930247F1E0ABE0DD5A63B087DBCB8464C3AA5CB361B726E0D0E17D1D548A0FD84B52` |
| SSDEEP | `1536:8pGMh60Wasw2EI+La0Tm1T+GvyHswN2UXlrUX9T9iT8/Z83ro:8pGME0e+eomJ+AyMwN2uJ0p9ipro` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_1bb6d17d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bb6d17dfbb9e9f568643559f62fd66066fcf965199de062552bba2b30c37df0"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-09-11 21:56:27"
  condition:
    hash.sha256(0, filesize) == "1bb6d17dfbb9e9f568643559f62fd66066fcf965199de062552bba2b30c37df0"
}
```

### Sample 70: `774a531c6b2a7a6a`

| Field | Value |
|---|---|
| SHA-256 | `774a531c6b2a7a6a10f94fcc74649dd6a20e79b7e06dae532c49e8b1fcf84c2f` |
| Family label | `unknown` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-09-11 21:53:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `032721a0a7c12ad1352a0b5e9f0a9ede` |
| SHA-1 | `4ac29c0419a32db0ea53410b50d662bb5adb1577` |
| SHA-256 | `774a531c6b2a7a6a10f94fcc74649dd6a20e79b7e06dae532c49e8b1fcf84c2f` |
| SHA3-384 | `510b4e8528779c7d3949985f547b2e20dfab5a47098d6f731cb4717cb5335e337bf13962343ba776615147008ca40b6c` |
| TLSH | `T158C3028AF5B14E92EBD94371DDBB83399F419F65FEC2C3108FEC9026A112498E329D15` |
| SSDEEP | `3072:zoZVmHmxDjoqP7dOumbWGKDW6rCdupBmTdMnje1cqCif5QqLdwbvNRx:z6xfdDmsWQsuY+j/qCif5QC2bvR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_774a531c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774a531c6b2a7a6a10f94fcc74649dd6a20e79b7e06dae532c49e8b1fcf84c2f"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-09-11 21:53:23"
  condition:
    hash.sha256(0, filesize) == "774a531c6b2a7a6a10f94fcc74649dd6a20e79b7e06dae532c49e8b1fcf84c2f"
}
```

### Sample 71: `923dbede92d58d7c`

| Field | Value |
|---|---|
| SHA-256 | `923dbede92d58d7c58199c91b8f6cbdafdd938337889879e8ec366c1bf4d0577` |
| Family label | `unknown` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-09-11 21:53:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45ed254c5724ff9a8abd4b951211c171` |
| SHA-1 | `65cf41276f9daf758045b7876107b6913e8498c9` |
| SHA-256 | `923dbede92d58d7c58199c91b8f6cbdafdd938337889879e8ec366c1bf4d0577` |
| SHA3-384 | `e8bedc670148f0f5466a91dc75e9975e2e60b6a1a8b4a9d5edcd5ec41fe8a47015af03ed8b4de62e0194e8dc111615a4` |
| TLSH | `T101A3016A494276DDECC40B3E50C7AA11BDA9E61E1DAFFC273AD9A1DC3EF0340B245445` |
| SSDEEP | `1536:OfP1cHCm79ccJoooOeQ2EXLkoXJQ8LJVcBj5ZQ6QkI8UTKngqm22jTRw8lmSdk4h:C1cz79Z5oOeQpXAiQ8diq6dIZGezJh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_923dbede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "923dbede92d58d7c58199c91b8f6cbdafdd938337889879e8ec366c1bf4d0577"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-09-11 21:53:22"
  condition:
    hash.sha256(0, filesize) == "923dbede92d58d7c58199c91b8f6cbdafdd938337889879e8ec366c1bf4d0577"
}
```

### Sample 72: `2250189b2c5c24f3`

| Field | Value |
|---|---|
| SHA-256 | `2250189b2c5c24f38393267d6e2a53ee7bf6068ce89dc16c27585831951d0b1f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 21:52:42` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `977452b59038c222073c0eac96ac681e` |
| SHA-1 | `980bb56bb9761a7adc1e173c288c65dfdc0a7972` |
| SHA-256 | `2250189b2c5c24f38393267d6e2a53ee7bf6068ce89dc16c27585831951d0b1f` |
| SHA3-384 | `ff3e897931840d2cb4b3135bcba3e2391b65eeb0ef9575b4290ad7b2a00fc8af1c092f4370ca9566156bc9103d365cfa` |
| IMPHASH | `f29039f5136c277872a4afb59337127a` |
| TLSH | `T187634C19BE87D7B8C449C874C35786634E6074CB1F34E7DF22E516692E2AAE81F3D224` |
| SSDEEP | `768:UCEMJPxk0OaXyZOESID/KisdKQMXQWg6EyEyB2DSLab0pk8SCUN0I4FkmGz:RV5ZCZFSIzC+AWg6EVycmLaQ28jtFyz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_2250189b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2250189b2c5c24f38393267d6e2a53ee7bf6068ce89dc16c27585831951d0b1f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 21:52:42"
  condition:
    hash.sha256(0, filesize) == "2250189b2c5c24f38393267d6e2a53ee7bf6068ce89dc16c27585831951d0b1f"
}
```

### Sample 73: `d3d007c14bda7812`

| Field | Value |
|---|---|
| SHA-256 | `d3d007c14bda781264dd314938122f6c7d3b772d5870787cfbaa992d4c251c61` |
| Family label | `unknown` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-09-11 21:51:19` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4dd036e11e9a0b3974359b747aa5bf1` |
| SHA-1 | `3f20e4e2e2047fe9f051d1d7f0a2acb8cc4088d6` |
| SHA-256 | `d3d007c14bda781264dd314938122f6c7d3b772d5870787cfbaa992d4c251c61` |
| SHA3-384 | `23c9527af7d7e7084abfb13ee1ea9381686105c45dc62e761c0fdd9c6713f195e5fb6b261722b4a2d964c3f0f6615491` |
| TLSH | `T10293021496C28F62EC293472D49B9B69BE408D8F3EE1774687AC63B04CDC57AC17CA17` |
| SSDEEP | `1536:8pGAth0Q0/IwWP+rTfIK2ZWY9nCSH15r4t3uoE5zMu7dbEacm/p9EIz5hunr6e3Q:8pGk2Q0/IwWPM69zHPc305zM2BEacwYQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_d3d007c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3d007c14bda781264dd314938122f6c7d3b772d5870787cfbaa992d4c251c61"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-09-11 21:51:19"
  condition:
    hash.sha256(0, filesize) == "d3d007c14bda781264dd314938122f6c7d3b772d5870787cfbaa992d4c251c61"
}
```

### Sample 74: `985cf05a00486d49`

| Field | Value |
|---|---|
| SHA-256 | `985cf05a00486d49bf1047e1071c4c47c15873dc3da4bb10fc444ffe48f32e3b` |
| Family label | `unknown` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-09-11 21:48:12` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2004095825a01356a53c1fbf5f55c7af` |
| SHA-1 | `942dec3632a53f82012aa4424c8fdf6b04b7af04` |
| SHA-256 | `985cf05a00486d49bf1047e1071c4c47c15873dc3da4bb10fc444ffe48f32e3b` |
| SHA3-384 | `b8f3760f746c5c817ab8e9e5f75a103993e577b1bd51bf1c96fe5eca24ec549d7fb0d6b47b569e042d69075799175e3e` |
| TLSH | `T1AAF30210FFA8894DDC930F70D86F4FC94AD7C1B207E5A18D6146A74AB92797C4227ABC` |
| SSDEEP | `3072:52uEEC7QljoF0PkcJzeSzonplX4nuzq2g61AE:GHuoF08gNonjguzLguA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_985cf05a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "985cf05a00486d49bf1047e1071c4c47c15873dc3da4bb10fc444ffe48f32e3b"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-09-11 21:48:12"
  condition:
    hash.sha256(0, filesize) == "985cf05a00486d49bf1047e1071c4c47c15873dc3da4bb10fc444ffe48f32e3b"
}
```

### Sample 75: `0e604973ecdd6fc6`

| Field | Value |
|---|---|
| SHA-256 | `0e604973ecdd6fc60aeeffed859f68e38217f018d6568c8270a611d82cc9dbd6` |
| Family label | `unknown` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-09-11 21:44:05` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec03c04c021b3f7859e5ce1a8695f454` |
| SHA-1 | `05f149062d265c49fedf4fe071510b4037f0ecf6` |
| SHA-256 | `0e604973ecdd6fc60aeeffed859f68e38217f018d6568c8270a611d82cc9dbd6` |
| SHA3-384 | `9c7391a9a2f7ac582f2dcdc24ed6b36cbc2d453d23a02320f19da997ca4fead166e6a6b70c034521ce413c2d3a2f41d5` |
| TLSH | `T16A93026AE2C19F73D8861B399593F143368FC0487123BBA68385856DC1EE177B8B4D27` |
| SSDEEP | `1536:4NWFOS/GUycRjwaRSW1pcHp61VgsJQwKzkYYCpY6hmrIxOrY4ChlO4b7OSUB9:4NW4Srj0WvApoJd/rIkrY4cb3Ur` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_0e604973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e604973ecdd6fc60aeeffed859f68e38217f018d6568c8270a611d82cc9dbd6"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-09-11 21:44:05"
  condition:
    hash.sha256(0, filesize) == "0e604973ecdd6fc60aeeffed859f68e38217f018d6568c8270a611d82cc9dbd6"
}
```

### Sample 76: `eddf6ba316a60044`

| Field | Value |
|---|---|
| SHA-256 | `eddf6ba316a60044c88ba8570d9bb0ad0ee4f91a4b017b844f5d4d42af8479bb` |
| Family label | `unknown` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-09-11 21:43:02` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `852cad84480a1919343a1053286fc733` |
| SHA-1 | `1f8d4ac688ff201ff55f398b5d4fb978de7aa7b0` |
| SHA-256 | `eddf6ba316a60044c88ba8570d9bb0ad0ee4f91a4b017b844f5d4d42af8479bb` |
| SHA3-384 | `656df6e2fd249231015d2fa1e3d9fe5e94c3a008e9768e7576122d1ef4edf44aea51d5b1d588715542bcfa2b4f19cfa6` |
| TLSH | `T13A930207E6D13EF1C9042ABA8153CB9871CBBC987CB5B543D072E57C98362E5C85AB4B` |
| SSDEEP | `1536:8pGAthKkbBERE1m3h3dmmsBZkEUZHnaWd/fsR85rvJlOnZHsV/lp+YqTH:8pGkQkiR3dvreuPlpVNp0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_eddf6ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eddf6ba316a60044c88ba8570d9bb0ad0ee4f91a4b017b844f5d4d42af8479bb"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-09-11 21:43:02"
  condition:
    hash.sha256(0, filesize) == "eddf6ba316a60044c88ba8570d9bb0ad0ee4f91a4b017b844f5d4d42af8479bb"
}
```

### Sample 77: `0859c524b8a63551`

| Field | Value |
|---|---|
| SHA-256 | `0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd` |
| Family label | `unknown` |
| File name | `0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd.exe` |
| File type | `exe` |
| First seen | `2026-09-11 21:39:36` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ece29f11bca82d84b4f06a0b73f127dc` |
| SHA-1 | `9eff75f1f9c2786a1807a220f3cd0f5279b45f5d` |
| SHA-256 | `0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd` |
| SHA3-384 | `0a7b317b99ffd3d6ce85127c36ca27d5f30a5de2607118fbf58394492026245ce6b45716cf4373e71f12fd2b4aa0c772` |
| IMPHASH | `d00af420812a39241f821fb057cc3154` |
| TLSH | `T117753365E36A9E9EE8AFD0B7CE3D02A3F2B2BC5C841DAF4F04C24A90DD7D255D014661` |
| SSDEEP | `24576:XUZY27AIDG+y6ln0ofg1iPQYudr10Vpx4H7o4MtZhEZzmaUbqAjmo5vW3AQbrx:XUu27AAFifiPo6U3MZkijmo5vW3AQbrx` |
| ICON-DHASH | `00b28eabababa600` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_0859c524
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd"
    family = "unknown"
    file_name = "0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd.exe"
    file_type = "exe"
    first_seen = "2026-09-11 21:39:36"
  condition:
    hash.sha256(0, filesize) == "0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd"
}
```

### Sample 78: `e9704311b60ac940`

| Field | Value |
|---|---|
| SHA-256 | `e9704311b60ac9400afb5819e273ccccc2093321c239610952e8f526c4388c66` |
| Family label | `Mirai` |
| File name | `bot.arm7` |
| File type | `elf` |
| First seen | `2026-09-11 21:35:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4736b83648d18ac9e90d36e8002f67e7` |
| SHA-1 | `a22f56981bb70076ccb9e1a835bc12956ed2b584` |
| SHA-256 | `e9704311b60ac9400afb5819e273ccccc2093321c239610952e8f526c4388c66` |
| SHA3-384 | `ae047095b964ddd5d3742355442ffec73b9c7b5053feb8fa2a21b0fdfa3ec01285c74e7eaf41c5b17fd860e2dc3af962` |
| TLSH | `T118F49E88E2F2EBCEE199E9355201BC064D66853730E37785724FA6B332771714BE9A20` |
| SSDEEP | `12288:LnlURzDx9YPmx/jjuUIcB5tVDtvniYm1vuWw9s0a9LgpPLk/vt:Bw5FjjuUIYtV1CvB1n3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_e9704311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9704311b60ac9400afb5819e273ccccc2093321c239610952e8f526c4388c66"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-09-11 21:35:24"
  condition:
    hash.sha256(0, filesize) == "e9704311b60ac9400afb5819e273ccccc2093321c239610952e8f526c4388c66"
}
```

### Sample 79: `0463f45c75df9ced`

| Field | Value |
|---|---|
| SHA-256 | `0463f45c75df9cedca6f373b259715888bf4696ec78f629ec3b2998a3036021e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-11 21:35:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7f15e5fb99d3449e658ac77fe88571a` |
| SHA-1 | `f9c048003cbe8ae7f36edddad868815b9339d97a` |
| SHA-256 | `0463f45c75df9cedca6f373b259715888bf4696ec78f629ec3b2998a3036021e` |
| SHA3-384 | `0904d9a938268fbefac5a813106dbce951cf4be1a01650df3f89050767d5f9902784d6a3f717014f49d125e940d2a402` |
| TLSH | `T117C28D956A867C44BEC94A3E4CBD2B0D6DF5C3D1324952AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:F9e8vCB+25j6es8RiZ9FYpMSUpi+20qUpi+20YQX:He8l25JId2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_0463f45c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0463f45c75df9cedca6f373b259715888bf4696ec78f629ec3b2998a3036021e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 21:35:22"
  condition:
    hash.sha256(0, filesize) == "0463f45c75df9cedca6f373b259715888bf4696ec78f629ec3b2998a3036021e"
}
```

### Sample 80: `620bf856545ecf10`

| Field | Value |
|---|---|
| SHA-256 | `620bf856545ecf108abad84aeea7eb41d96667a2c6412810fabbee2e8ef08144` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 21:27:14` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63f7e08f4636894e70bef277d050b707` |
| SHA-256 | `620bf856545ecf108abad84aeea7eb41d96667a2c6412810fabbee2e8ef08144` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_620bf856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620bf856545ecf108abad84aeea7eb41d96667a2c6412810fabbee2e8ef08144"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 21:27:14"
  condition:
    hash.sha256(0, filesize) == "620bf856545ecf108abad84aeea7eb41d96667a2c6412810fabbee2e8ef08144"
}
```

### Sample 81: `80957b43a59cc8eb`

| Field | Value |
|---|---|
| SHA-256 | `80957b43a59cc8eb7fd66ba361edc8bbefa45e1d5e8d64de8e043f430e01320d` |
| Family label | `unknown` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-09-11 21:24:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `429fa8407a7563a09c5c9cc58a593a49` |
| SHA-1 | `b329c43fa1046b2fc2cbd86b0563d5f0b025ce90` |
| SHA-256 | `80957b43a59cc8eb7fd66ba361edc8bbefa45e1d5e8d64de8e043f430e01320d` |
| SHA3-384 | `97e01581d01eca61477e44c55640bdea429c01999960d5c084e2b8373f6f05dc8699c96c26007cc2f649e33e77cdc833` |
| TLSH | `T19BA30273F74BF461E900B331044577FB80777C3939DE6A964BD39928A530BAD0A69E22` |
| SSDEEP | `3072:McP+Xhaw8gTHVgR+dKVKxmARObJIjrxIGk:EXD8g1gkoQZRqIpI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_80957b43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80957b43a59cc8eb7fd66ba361edc8bbefa45e1d5e8d64de8e043f430e01320d"
    family = "unknown"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-09-11 21:24:09"
  condition:
    hash.sha256(0, filesize) == "80957b43a59cc8eb7fd66ba361edc8bbefa45e1d5e8d64de8e043f430e01320d"
}
```

### Sample 82: `3f8a269735332db5`

| Field | Value |
|---|---|
| SHA-256 | `3f8a269735332db54cef58223415138998c4201b84d8269cdf6f2c3f862b10bd` |
| Family label | `unknown` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-09-11 21:24:08` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42c741d4772de82c21f7d1f0a6ff4351` |
| SHA-1 | `cc3211e69c6c8cd7a2481d99acb1e23d42911a44` |
| SHA-256 | `3f8a269735332db54cef58223415138998c4201b84d8269cdf6f2c3f862b10bd` |
| SHA3-384 | `34e520384425f0178e2bd41f0d8454dc121c9eaa9bcfe8c02ef777796770ad33c0c6e0bdc3d3ace3f432bd4fd1b823c5` |
| TLSH | `T1A693120BC2C06DDAE8351B78DD93D100E408854CB5DC77D27528CE669DBA06E64B9F9C` |
| SSDEEP | `1536:8pGihxwimDcTiW8HqzqEsmg16bRc9GeUo580U+ygoof1R9iccd1RgvDJzr00xN/q:8pGizwnXWRGEsL6bReGd0U+ynof1E2JM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_3f8a2697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f8a269735332db54cef58223415138998c4201b84d8269cdf6f2c3f862b10bd"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-09-11 21:24:08"
  condition:
    hash.sha256(0, filesize) == "3f8a269735332db54cef58223415138998c4201b84d8269cdf6f2c3f862b10bd"
}
```

### Sample 83: `c8fd1ce67cac8f8b`

| Field | Value |
|---|---|
| SHA-256 | `c8fd1ce67cac8f8bf4f2ced77f82cca4ddcc3ab084040898776e30c962c055ff` |
| Family label | `unknown` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-09-11 21:24:07` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71c9669678a0b869e07e25d11cf21c12` |
| SHA-1 | `7b2fd85ab33e9a50baa9278c80b11b17de16658e` |
| SHA-256 | `c8fd1ce67cac8f8bf4f2ced77f82cca4ddcc3ab084040898776e30c962c055ff` |
| SHA3-384 | `ffc09f2ca436d836e46f45cb34087e48760b5fa3a59d347af3867896d4ed49ab276362e802ab8bf5dd04a4bfc4e83cda` |
| TLSH | `T1D5A3F116DA21ADC5CD19F374982DF7976F71F8582AB06A661F77A82C393BD304C01E21` |
| TELFHASH | `t1d6c0129213103ce223070c017221d1aace020873ba213a2d33398cf8aa20b058901010` |
| SSDEEP | `1536:d2/8ofIdD8Eqn0RsJJ6V8terhhXTvU7g+deUu9avAmqfoAVixbTX/6rT:d2NypM6VAqDzVUu90VqwAVi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_c8fd1ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8fd1ce67cac8f8bf4f2ced77f82cca4ddcc3ab084040898776e30c962c055ff"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-09-11 21:24:07"
  condition:
    hash.sha256(0, filesize) == "c8fd1ce67cac8f8bf4f2ced77f82cca4ddcc3ab084040898776e30c962c055ff"
}
```

### Sample 84: `36c8e66b56a21a7a`

| Field | Value |
|---|---|
| SHA-256 | `36c8e66b56a21a7a9d30ecde90d096d037c8e30a0596a66ddf30fa221a0bbc96` |
| Family label | `unknown` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-09-11 21:13:11` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95690d6b0f2a4bbab76d7f724ef9ee4d` |
| SHA-1 | `7938c0da3e6caa5821088d79c60cd9cbc1481b8e` |
| SHA-256 | `36c8e66b56a21a7a9d30ecde90d096d037c8e30a0596a66ddf30fa221a0bbc96` |
| SHA3-384 | `82252a0f7786740e38f4bd5cbf2c0c588807b4f794d8be55c55d606614708bc5b57f86a64bb52e70da62f7a8a0dddb7b` |
| TLSH | `T19DC302C3B3A14E95F792CB70FDBB432A5FD25F648787831D8E86E024B144B88B52AD14` |
| SSDEEP | `3072:1AaUoMJ4hA6lpq14H8SM0WZ+UVy0PmKX8Vjo34LQzgj:1I2hA6OKSZl+KXW9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_36c8e66b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36c8e66b56a21a7a9d30ecde90d096d037c8e30a0596a66ddf30fa221a0bbc96"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-09-11 21:13:11"
  condition:
    hash.sha256(0, filesize) == "36c8e66b56a21a7a9d30ecde90d096d037c8e30a0596a66ddf30fa221a0bbc96"
}
```

### Sample 85: `d7930ec34b23b972`

| Field | Value |
|---|---|
| SHA-256 | `d7930ec34b23b972555b6ccd5ea1c333a04631b791f54820c5b9df8f11bddd3d` |
| Family label | `unknown` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-09-11 21:05:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5da494ea42ec283ebdea9b2d783ee6cd` |
| SHA-1 | `71682e9cc9884500d04b9cfdb3e658347edb0a71` |
| SHA-256 | `d7930ec34b23b972555b6ccd5ea1c333a04631b791f54820c5b9df8f11bddd3d` |
| SHA3-384 | `93dff977234f86dd7c845097409c8e87e4774e1a57da0ec45d0fc9f030b816d686d1ba3f98674acd4e5b3a6624f9d9dd` |
| TLSH | `T19CC3028673C14FB2E6598B73A4CF839577A3DA55CFC243194E29B838224C748FA25C68` |
| SSDEEP | `3072:0bCrQaRBDS7EOM8FmWngpH/JvS7+4lF1qEsOjq5zyOA22F0G:0o0EOKpx6iVZWF0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_d7930ec3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7930ec34b23b972555b6ccd5ea1c333a04631b791f54820c5b9df8f11bddd3d"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-09-11 21:05:06"
  condition:
    hash.sha256(0, filesize) == "d7930ec34b23b972555b6ccd5ea1c333a04631b791f54820c5b9df8f11bddd3d"
}
```

### Sample 86: `4a84d21194b584be`

| Field | Value |
|---|---|
| SHA-256 | `4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e` |
| Family label | `unknown` |
| File name | `4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e.sh` |
| File type | `sh` |
| First seen | `2026-09-11 20:47:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87d418fb188a8ec8c8a4bbbadf573cd4` |
| SHA-1 | `5c3d896ec3c6fe52359182ca403e3914c072cd4b` |
| SHA-256 | `4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e` |
| SHA3-384 | `f063ec1588520c5b43357f7c44ab6112032bffcfa68ef907bfb50b16f414b72d2eea3e107989ac6a511fa3c7d785757f` |
| TLSH | `T17651757024F04C332E656580F3372BA6ABB7E95349E3618C35DE1E396F87B12A5AF411` |
| SSDEEP | `48:cnRu9Rp9nB6gwUblrk+3l/BZpklrMZlClriZlClrXZlClrWZlClrRn:cRu7B6oxTcxHoDF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_4a84d211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e"
    family = "unknown"
    file_name = "4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e.sh"
    file_type = "sh"
    first_seen = "2026-09-11 20:47:01"
  condition:
    hash.sha256(0, filesize) == "4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e"
}
```

### Sample 87: `135764ae4337fbf9`

| Field | Value |
|---|---|
| SHA-256 | `135764ae4337fbf9f8bc3119f6f83eebfc8df847a3fd2f33f25e0ded54f7dc46` |
| Family label | `unknown` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-09-11 20:25:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bdacb2f861a7d2a70d21ae253c8b66e` |
| SHA-1 | `b5cc25d57147a040daaa01e857ae578fdaa55936` |
| SHA-256 | `135764ae4337fbf9f8bc3119f6f83eebfc8df847a3fd2f33f25e0ded54f7dc46` |
| SHA3-384 | `29ef45eab035f7face527dc2842450845f5564e37b4cd99097a4a954ecaf2dcab5294bb4552b01d1e827dbb2f31dc3eb` |
| TLSH | `T186A30113A842394DD945933A61C7F33ABD57DA32E7ABFC97769AF9343F382405289140` |
| SSDEEP | `1536:ud1E7uXDAwQCUT5YNAyBpITom2w9PLvtiTrtBmyERmKMGzjLuSH1jBBIy3fCQ2:uEiXDATtYNAqm32aLv0toyozjTH1jBr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_135764ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135764ae4337fbf9f8bc3119f6f83eebfc8df847a3fd2f33f25e0ded54f7dc46"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-09-11 20:25:04"
  condition:
    hash.sha256(0, filesize) == "135764ae4337fbf9f8bc3119f6f83eebfc8df847a3fd2f33f25e0ded54f7dc46"
}
```

### Sample 88: `681ed8e2061fda8b`

| Field | Value |
|---|---|
| SHA-256 | `681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8` |
| Family label | `unknown` |
| File name | `681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8.sh` |
| File type | `sh` |
| First seen | `2026-09-11 20:24:02` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `feb501aebdc88a1fda4f75eb34234128` |
| SHA-1 | `88797319f2a40c6667645bda4415bce5851e3b64` |
| SHA-256 | `681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8` |
| SHA3-384 | `c4b1d9192a2fd49eb41fc89e7399937a638209d4358459958da7429f6400999f404bead976a9a93e30a54c75a79e740a` |
| TLSH | `T12832A17525F14C333A705984B3772BA2ABB6D95385E3218C35DE2E266F86F02B1AF411` |
| SSDEEP | `96:cRuKB6es5FUJRxG22lQxfafW5SKSOSCgHSajmYmFZ6x5b/U0:cRuu6ernThW/3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_681ed8e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8"
    family = "unknown"
    file_name = "681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8.sh"
    file_type = "sh"
    first_seen = "2026-09-11 20:24:02"
  condition:
    hash.sha256(0, filesize) == "681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8"
}
```

### Sample 89: `dbac862805f4b4e1`

| Field | Value |
|---|---|
| SHA-256 | `dbac862805f4b4e1b426ed441bf4c4d2c9523ef17189759294f2d3cfeb88e9a2` |
| Family label | `unknown` |
| File name | `b` |
| File type | `unknown` |
| First seen | `2026-09-11 20:09:08` |
| Reporter | `monitorsg` |
| Tags | `KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d719acb97e687935689b91a5f77889e` |
| SHA-256 | `dbac862805f4b4e1b426ed441bf4c4d2c9523ef17189759294f2d3cfeb88e9a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_dbac8628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbac862805f4b4e1b426ed441bf4c4d2c9523ef17189759294f2d3cfeb88e9a2"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-11 20:09:08"
  condition:
    hash.sha256(0, filesize) == "dbac862805f4b4e1b426ed441bf4c4d2c9523ef17189759294f2d3cfeb88e9a2"
}
```

### Sample 90: `ca3ebe2ce77f73fa`

| Field | Value |
|---|---|
| SHA-256 | `ca3ebe2ce77f73faf246331eff19f8c33966520ff7c3369d83d244dfdbda0a1a` |
| Family label | `RemusStealer` |
| File name | `Real Executor.exe` |
| File type | `exe` |
| First seen | `2026-09-11 19:46:20` |
| Reporter | `anonymous` |
| Tags | `exe, Remus, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f19ef8c19bba9dd01d5b820d6fa51648` |
| SHA-1 | `3a925ae40d7be4b9409d5f7eb1de4f7e6e8b7e62` |
| SHA-256 | `ca3ebe2ce77f73faf246331eff19f8c33966520ff7c3369d83d244dfdbda0a1a` |
| SHA3-384 | `1a1dbb9529a56a9d91cc4f5bee59aeddf20ea80bee08b6e1617731a60a6f2547f8fec889a6f6a585f272c9277b7b45fe` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T11D465B03AE6964D9C89DD674C9B70152BB707C894B3263D70E94AA343FBBBD0AD79301` |
| SSDEEP | `49152:PK1+e4GOavSm9yIgC99RkPw7zf3nNTsdpdNCwrNIiLopJbnLylqHI70n1MsLSnSr:PK1H4RsJrRHF2dQL07SmY` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_090_ca3ebe2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca3ebe2ce77f73faf246331eff19f8c33966520ff7c3369d83d244dfdbda0a1a"
    family = "RemusStealer"
    file_name = "Real Executor.exe"
    file_type = "exe"
    first_seen = "2026-09-11 19:46:20"
  condition:
    hash.sha256(0, filesize) == "ca3ebe2ce77f73faf246331eff19f8c33966520ff7c3369d83d244dfdbda0a1a"
}
```

### Sample 91: `a36ee55b82476064`

| Field | Value |
|---|---|
| SHA-256 | `a36ee55b824760641e9c06a8b30fc2ed23851bc49da254c61a68fdcf4b192bf0` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.msi` |
| File type | `msi` |
| First seen | `2026-09-11 19:44:05` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a6657447868d9f52281727fbcec196d` |
| SHA-1 | `52c44aef81a852e630850033579135019dfea6e7` |
| SHA-256 | `a36ee55b824760641e9c06a8b30fc2ed23851bc49da254c61a68fdcf4b192bf0` |
| SHA3-384 | `3f07d35b8463934ff27ff85f1246d93b9e994023142d51d7cc917ceca18779fde05b689de687169769b542cca311d8dc` |
| TLSH | `T111D6232267FD0A18E1F36778ED3A90E19536BC65DF12D08F2654386E6871E4093A373B` |
| SSDEEP | `196608:DrnLYG3zDhukO9rnLYG3z9rnLYG3zprnLYG3zirnLYG3zIrnLYG3zprnLYG3z:DbDDDgv9bDD9bDDpbDDibDDIbDDpbDD` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_091_a36ee55b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a36ee55b824760641e9c06a8b30fc2ed23851bc49da254c61a68fdcf4b192bf0"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-11 19:44:05"
  condition:
    hash.sha256(0, filesize) == "a36ee55b824760641e9c06a8b30fc2ed23851bc49da254c61a68fdcf4b192bf0"
}
```

### Sample 92: `9654e2f8add456b4`

| Field | Value |
|---|---|
| SHA-256 | `9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e` |
| Family label | `unknown` |
| File name | `9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e.sh` |
| File type | `sh` |
| First seen | `2026-09-11 19:41:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4db5d8c9a6f2304c3f19ceffb223cfe3` |
| SHA-1 | `7862fb33020789658c18baf447939db32b47dd77` |
| SHA-256 | `9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e` |
| SHA3-384 | `7e429bd57fadf2cb51ba1c165edc81fd443d3da93c47ff559e4fa4ea6c872020dca33f29d70e6392eef4b9aad6eeba49` |
| TLSH | `T17032D67025F18D732E25AA80B3372BA69BB6D95345E3318C35DD2E265F87B12A0FF411` |
| SSDEEP | `96:cCu3k0B6VzYMPZo8zS+6+x+s6IBqHIBZIBcIBSIBrIB4IBNIBrIBFcDfBVZUdR1m:cCu0g6VjZYBe4Tm/9g/C45hfp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_9654e2f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e"
    family = "unknown"
    file_name = "9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e.sh"
    file_type = "sh"
    first_seen = "2026-09-11 19:41:10"
  condition:
    hash.sha256(0, filesize) == "9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e"
}
```

### Sample 93: `9e725f4893d50fcc`

| Field | Value |
|---|---|
| SHA-256 | `9e725f4893d50fccea212a96359489cb36a00e8f397ebbb2e712278b124c5567` |
| Family label | `unknown` |
| File name | `Bootstrler_v31.0.534.exe` |
| File type | `exe` |
| First seen | `2026-09-11 19:40:17` |
| Reporter | `anonymous` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fa9cb6d1a2870300c8e4b2022996878` |
| SHA-1 | `d6bd2b5f3c599e1cb2dd128bddb83e3474971385` |
| SHA-256 | `9e725f4893d50fccea212a96359489cb36a00e8f397ebbb2e712278b124c5567` |
| SHA3-384 | `54e80a1b0129ed7de1f18bd4bfbb92137bd09d66f3518e45e53e7665bf4c165b22c21465a9aeb250fa233b8a7cc2037d` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T1FDC64A1759005194EC958E38D87BA261F734BC4ED7B2336B8D11A6B42F273C2BEB9B44` |
| SSDEEP | `196608:3GI1vKTS1YnZq2T25E6JBif6o+DRANCP8YAL4pXxKbc:3RoDT25E6JBif6ouANCPYs7Ko` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_9e725f48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e725f4893d50fccea212a96359489cb36a00e8f397ebbb2e712278b124c5567"
    family = "unknown"
    file_name = "Bootstrler_v31.0.534.exe"
    file_type = "exe"
    first_seen = "2026-09-11 19:40:17"
  condition:
    hash.sha256(0, filesize) == "9e725f4893d50fccea212a96359489cb36a00e8f397ebbb2e712278b124c5567"
}
```

### Sample 94: `db3cf6dae0646bbe`

| Field | Value |
|---|---|
| SHA-256 | `db3cf6dae0646bbe3715d66efb5efdc0a42c96efbbe4166e043d890a1a74c2db` |
| Family label | `ConnectWise` |
| File name | `Installer.msi` |
| File type | `msi` |
| First seen | `2026-09-11 19:36:49` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3790fe18ecb8f14747f133508421bbc0` |
| SHA-1 | `5884cfe792a0797f5b96805f76a512f3ed168141` |
| SHA-256 | `db3cf6dae0646bbe3715d66efb5efdc0a42c96efbbe4166e043d890a1a74c2db` |
| SHA3-384 | `a045d563fae2055eb162ac023e3c2310d25ffdb9631aac63f19f7a7372fc20467239711e48939868734843ca92962961` |
| TLSH | `T156E623116BF89668F1F22A79E876A071A13B7C125D36D12E2324791E2C75EC0C9B3737` |
| SSDEEP | `196608:mHxcp9ym3nltDUJVeHxcp9ym3yHxcp9ym3DHxcp9ym3OHxcp9ym3dAHxcp9ym3d7:0GplpNGpAGptGpcGpduGpd/Gpdc` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_094_db3cf6da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3cf6dae0646bbe3715d66efb5efdc0a42c96efbbe4166e043d890a1a74c2db"
    family = "ConnectWise"
    file_name = "Installer.msi"
    file_type = "msi"
    first_seen = "2026-09-11 19:36:49"
  condition:
    hash.sha256(0, filesize) == "db3cf6dae0646bbe3715d66efb5efdc0a42c96efbbe4166e043d890a1a74c2db"
}
```

### Sample 95: `1ba8c6b1a58b294e`

| Field | Value |
|---|---|
| SHA-256 | `1ba8c6b1a58b294eb15e4f846b141fdda793f834e340767515d89609de5802ad` |
| Family label | `ConnectWise` |
| File name | `E-Invite.vbs` |
| File type | `vbs` |
| First seen | `2026-09-11 19:32:33` |
| Reporter | `BastianHein_` |
| Tags | `Connectwise, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b40cf0dd4fe3f2d72764f8c47b973aaf` |
| SHA-1 | `e8629d5eaa105c9515cf724c026afda2489d3c67` |
| SHA-256 | `1ba8c6b1a58b294eb15e4f846b141fdda793f834e340767515d89609de5802ad` |
| SHA3-384 | `c0a99aed203fe43a59b4e5d9ddf0766d198cba3c16bbe0d0b13e6d5743b60ed0ae54258b97909f3e79fc9e51d0a28bfc` |
| TLSH | `T1D78212B110A6E6DB8319E017B235841D6767E2284277323738FB170D8B3FED6D7592A1` |
| SSDEEP | `192:eGGRaGGHd43QBZilcR30pu4N59hHR6q47oqGbc7vQqF7+4+6/1/DO2KVnrVoxSc4:GR1k6fx4WgzJF7jZDO2KZW/+8jIT` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_095_1ba8c6b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ba8c6b1a58b294eb15e4f846b141fdda793f834e340767515d89609de5802ad"
    family = "ConnectWise"
    file_name = "E-Invite.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 19:32:33"
  condition:
    hash.sha256(0, filesize) == "1ba8c6b1a58b294eb15e4f846b141fdda793f834e340767515d89609de5802ad"
}
```

### Sample 96: `7583a696c82d6604`

| Field | Value |
|---|---|
| SHA-256 | `7583a696c82d66041cf8778d18c99ebc142dafde43f37fbe5dd088af6cad0fe8` |
| Family label | `ConnectWise` |
| File name | `E-Invite.iso` |
| File type | `iso` |
| First seen | `2026-09-11 19:32:20` |
| Reporter | `BastianHein_` |
| Tags | `Connectwise, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b457eed632aef2dc8c5f1792ec223b1` |
| SHA-1 | `7b339aca0518c934e04751b2be53f70d0c9e2802` |
| SHA-256 | `7583a696c82d66041cf8778d18c99ebc142dafde43f37fbe5dd088af6cad0fe8` |
| SHA3-384 | `f47f8cb1e74c0985872ea105852097cb44d815ff7c2cf3e4b9a5092fdf75c396fd8d5ddd8f0ff95036d52a67ca2d5c80` |
| TLSH | `T15083EDB110A6E6DBC319E037B23584196767E22842B7322738FE170D8B3FED6D6553A1` |
| SSDEEP | `192:JoufXt4cGGRaGGHd43QBZilcR30pu4N59hHR6q47oqGbc7vQqF7+4+6/1/DO2KVj:Su11R1k6fx4WgzJF7jZDO2KZW/+8jI` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_096_7583a696
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7583a696c82d66041cf8778d18c99ebc142dafde43f37fbe5dd088af6cad0fe8"
    family = "ConnectWise"
    file_name = "E-Invite.iso"
    file_type = "iso"
    first_seen = "2026-09-11 19:32:20"
  condition:
    hash.sha256(0, filesize) == "7583a696c82d66041cf8778d18c99ebc142dafde43f37fbe5dd088af6cad0fe8"
}
```

### Sample 97: `1ecf72ad88cb8cda`

| Field | Value |
|---|---|
| SHA-256 | `1ecf72ad88cb8cda3263dcd384dc4a460d2339b3f79d352d20050ebf07cf7310` |
| Family label | `unknown` |
| File name | `Frostix.exe` |
| File type | `exe` |
| First seen | `2026-09-11 19:29:37` |
| Reporter | `anonymous` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1843e7ba667360c30a205c31f75216d0` |
| SHA-1 | `ae6442bd6b7cb258e2c5f40cae3319e454e55247` |
| SHA-256 | `1ecf72ad88cb8cda3263dcd384dc4a460d2339b3f79d352d20050ebf07cf7310` |
| SHA3-384 | `cf52a4853e1d5fc72a982ac81b3009447697840a0867679d7e458de1760f49fb4b99f57088aa2f1fa8b3cb91d3a83a60` |
| IMPHASH | `29b2911a6391bea4a7a6f261eb76ceb1` |
| TLSH | `T1504723E256E462F8D3938B09E2C7138683C1319BEA979B1D35C654032621DD7CF4AE7B` |
| SSDEEP | `786432:u8lFnzp6+q2GvpRpee0J5JwZ47Uc9u23qG6:u83Dq2Wqeawe4ou1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_1ecf72ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ecf72ad88cb8cda3263dcd384dc4a460d2339b3f79d352d20050ebf07cf7310"
    family = "unknown"
    file_name = "Frostix.exe"
    file_type = "exe"
    first_seen = "2026-09-11 19:29:37"
  condition:
    hash.sha256(0, filesize) == "1ecf72ad88cb8cda3263dcd384dc4a460d2339b3f79d352d20050ebf07cf7310"
}
```

### Sample 98: `1705283904501e94`

| Field | Value |
|---|---|
| SHA-256 | `1705283904501e94a2573166083e76aa90adb98d647cfe30769ea1948805f086` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 19:22:16` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c28797e673ca46aa9206bbced2a4476` |
| SHA-256 | `1705283904501e94a2573166083e76aa90adb98d647cfe30769ea1948805f086` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_17052839
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1705283904501e94a2573166083e76aa90adb98d647cfe30769ea1948805f086"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 19:22:16"
  condition:
    hash.sha256(0, filesize) == "1705283904501e94a2573166083e76aa90adb98d647cfe30769ea1948805f086"
}
```

### Sample 99: `d73ee5f1b3855f67`

| Field | Value |
|---|---|
| SHA-256 | `d73ee5f1b3855f67fa6e09a0ff4a288d27349902123625c89aa0caf22427af8a` |
| Family label | `GoToResolve` |
| File name | `crm.msi` |
| File type | `msi` |
| First seen | `2026-09-11 19:21:13` |
| Reporter | `BastianHein_` |
| Tags | `GoToResolve, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a2dba63ed3ae20444065a69a77158a7` |
| SHA-1 | `1f4c7e23e57bcadd74265b27117aca57995af20e` |
| SHA-256 | `d73ee5f1b3855f67fa6e09a0ff4a288d27349902123625c89aa0caf22427af8a` |
| SHA3-384 | `e869a6bdd82c813efd722b7e46da57ed59dfb1cb823d29e4019a453c5cb87ec5a8cd277352a886b32cdf8ab7e1616307` |
| TLSH | `T117872217A2E61154D8BAD138CA6B9647FB723C06433066DF12A4B61A6F73BF01A7F314` |
| SSDEEP | `786432:kfBBz66DIpCRkxjRlKjP1UrZ21G7KulNNm:kfBF66iGkxCtyZ2E7KN` |

#### Technical Assessment

- The sample is tracked as `GoToResolve` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoToResolve_099_d73ee5f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d73ee5f1b3855f67fa6e09a0ff4a288d27349902123625c89aa0caf22427af8a"
    family = "GoToResolve"
    file_name = "crm.msi"
    file_type = "msi"
    first_seen = "2026-09-11 19:21:13"
  condition:
    hash.sha256(0, filesize) == "d73ee5f1b3855f67fa6e09a0ff4a288d27349902123625c89aa0caf22427af8a"
}
```

### Sample 100: `e68f2fd161378cad`

| Field | Value |
|---|---|
| SHA-256 | `e68f2fd161378cad6e3a51312b21a87971851d59a59257be6b4f8a868cc18569` |
| Family label | `GoToResolve` |
| File name | `ivCardco.vbs` |
| File type | `vbs` |
| First seen | `2026-09-11 19:20:31` |
| Reporter | `BastianHein_` |
| Tags | `Gotoresolve, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `047e26b54da91a6839519d0d49f9a8e2` |
| SHA-1 | `23455d7254b59153d41d0189512477aafb944332` |
| SHA-256 | `e68f2fd161378cad6e3a51312b21a87971851d59a59257be6b4f8a868cc18569` |
| SHA3-384 | `8a3dd6937c38969e1564046c5f95053b493efc28a82c22084863987d6ddb9c63e1a9769b3e660efee03334ac02711204` |
| TLSH | `T12B5174CB540B8D470AB24A6AD1450D1ECEE4D35F5637C868BD5CE80D5B38268A3A60BE` |
| SSDEEP | `48:qgA36+tdATh0F2aA+COk6wmkZXxvckKNZFhQDi+OkRO78WMUW/u:9A3ghgLvwdHOZ8s2O7RMUWW` |

#### Technical Assessment

- The sample is tracked as `GoToResolve` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoToResolve_100_e68f2fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e68f2fd161378cad6e3a51312b21a87971851d59a59257be6b4f8a868cc18569"
    family = "GoToResolve"
    file_name = "ivCardco.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 19:20:31"
  condition:
    hash.sha256(0, filesize) == "e68f2fd161378cad6e3a51312b21a87971851d59a59257be6b4f8a868cc18569"
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
 * Generated: 2026-09-12T04:42:47.814941+00:00
 */

rule MalwareBazaar_unknown_001_99c90c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99c90c3796f9d0212669d4a4d4f3749fddb890fdb570cd0e3165bb8870a2136a"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-09-12 04:38:13"
  condition:
    hash.sha256(0, filesize) == "99c90c3796f9d0212669d4a4d4f3749fddb890fdb570cd0e3165bb8870a2136a"
}

rule MalwareBazaar_Mirai_002_b98ed7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98ed7a5c645421acd5462f2b3ed759087bfbe16890fe4c471e76c8d1ab35c8a"
    family = "Mirai"
    file_name = "libwind.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:41"
  condition:
    hash.sha256(0, filesize) == "b98ed7a5c645421acd5462f2b3ed759087bfbe16890fe4c471e76c8d1ab35c8a"
}

rule MalwareBazaar_Mirai_003_5002282e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5002282edb86e86fd7d7eedd8b3bd2444390eec0d18e93641d23c89cdba1f9ef"
    family = "Mirai"
    file_name = "libyahu.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:39"
  condition:
    hash.sha256(0, filesize) == "5002282edb86e86fd7d7eedd8b3bd2444390eec0d18e93641d23c89cdba1f9ef"
}

rule MalwareBazaar_unknown_004_da37e1ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da37e1eef108b5eba7563e5b1f0950dd1852bf9cf921910b24b57291806c375f"
    family = "unknown"
    file_name = "deepfield.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:36"
  condition:
    hash.sha256(0, filesize) == "da37e1eef108b5eba7563e5b1f0950dd1852bf9cf921910b24b57291806c375f"
}

rule MalwareBazaar_Mirai_005_b200ab6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-12 04:32:33"
  condition:
    hash.sha256(0, filesize) == "b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb"
}

rule MalwareBazaar_Mirai_006_895a9274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "895a9274620e8d9c48ddf330df8b9d7331322ea659c35d8808c381add741a89a"
    family = "Mirai"
    file_name = "com.imjustafriendlyguy.firmware.apk"
    file_type = "apk"
    first_seen = "2026-09-12 04:32:30"
  condition:
    hash.sha256(0, filesize) == "895a9274620e8d9c48ddf330df8b9d7331322ea659c35d8808c381add741a89a"
}

rule MalwareBazaar_unknown_007_086c60e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086c60e9b4fe2ea121130220fcae8185e2b3b7734a8208f434f064b654e7d872"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 04:28:26"
  condition:
    hash.sha256(0, filesize) == "086c60e9b4fe2ea121130220fcae8185e2b3b7734a8208f434f064b654e7d872"
}

rule MalwareBazaar_unknown_008_40f9fdac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f9fdac9ab5160d7e596c163a3868efbfdce437fc9e99815fdb6dc469029a2a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-12 04:21:21"
  condition:
    hash.sha256(0, filesize) == "40f9fdac9ab5160d7e596c163a3868efbfdce437fc9e99815fdb6dc469029a2a"
}

rule MalwareBazaar_unknown_009_e870ba42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e870ba426cd9bd8542b413641a456b6f1eab480a88eb2d83d644c1461a524919"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 04:21:20"
  condition:
    hash.sha256(0, filesize) == "e870ba426cd9bd8542b413641a456b6f1eab480a88eb2d83d644c1461a524919"
}

rule MalwareBazaar_unknown_010_48bc5bcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48bc5bcd4ef81298eacb98ab6f63cd9c3bdfadd917dea63c4af0ee470ea2cd18"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 04:19:32"
  condition:
    hash.sha256(0, filesize) == "48bc5bcd4ef81298eacb98ab6f63cd9c3bdfadd917dea63c4af0ee470ea2cd18"
}

rule MalwareBazaar_unknown_011_d7079114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7079114f00c0265e3553cd10f8816298c806a8b37402bfb4192ae9b8b9fc951"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-09-12 04:10:39"
  condition:
    hash.sha256(0, filesize) == "d7079114f00c0265e3553cd10f8816298c806a8b37402bfb4192ae9b8b9fc951"
}

rule MalwareBazaar_unknown_012_d3c34baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3c34baf4731aeffc5be0d1b6d2eb4ca4bddf35af1a1a79877bdc687189f857f"
    family = "unknown"
    file_name = "libsupport.so"
    file_type = "elf"
    first_seen = "2026-09-12 04:09:25"
  condition:
    hash.sha256(0, filesize) == "d3c34baf4731aeffc5be0d1b6d2eb4ca4bddf35af1a1a79877bdc687189f857f"
}

rule MalwareBazaar_unknown_013_28fd91c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28fd91c15efccb7678249f03890952819453df461eef83ef1b12a562f9d35ac4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-12 04:01:26"
  condition:
    hash.sha256(0, filesize) == "28fd91c15efccb7678249f03890952819453df461eef83ef1b12a562f9d35ac4"
}

rule MalwareBazaar_unknown_014_5ad6770b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ad6770bf4ad965f1a280ecc28de35ffa39eb4e174174b968f5dbd56e110f4ab"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-09-12 03:52:23"
  condition:
    hash.sha256(0, filesize) == "5ad6770bf4ad965f1a280ecc28de35ffa39eb4e174174b968f5dbd56e110f4ab"
}

rule MalwareBazaar_unknown_015_fede8fbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fede8fbf1f1795ddbd9283c5ad2f74869820759fa49b6adb1113df4e19cca3b6"
    family = "unknown"
    file_name = "ecf4307739ca93f1569ce49377a28b31fe1eb0f44b6950dbaafa1925b24c9752.dll"
    file_type = "exe"
    first_seen = "2026-09-12 03:51:45"
  condition:
    hash.sha256(0, filesize) == "fede8fbf1f1795ddbd9283c5ad2f74869820759fa49b6adb1113df4e19cca3b6"
}

rule MalwareBazaar_unknown_016_d56c1631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d56c1631b2f816bd9cac1c74bd640404556bb00c4567830d951c75fb7f70c122"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 03:49:33"
  condition:
    hash.sha256(0, filesize) == "d56c1631b2f816bd9cac1c74bd640404556bb00c4567830d951c75fb7f70c122"
}

rule MalwareBazaar_unknown_017_79624d5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79624d5fbbc9dbca866a3971b801eba6f99450b5340bf434fcd6d182dfe8a479"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-09-12 03:35:37"
  condition:
    hash.sha256(0, filesize) == "79624d5fbbc9dbca866a3971b801eba6f99450b5340bf434fcd6d182dfe8a479"
}

rule MalwareBazaar_unknown_018_bdd4b119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdd4b1198ebbfc963373747ee0bf6d0141e0601545c88fff80a9aa1300a8e867"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 03:34:22"
  condition:
    hash.sha256(0, filesize) == "bdd4b1198ebbfc963373747ee0bf6d0141e0601545c88fff80a9aa1300a8e867"
}

rule MalwareBazaar_unknown_019_5b00c60a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b00c60a45f81997c20465d87982b3a33cae3c02ecf62240b0f56172782ed5a9"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-09-12 03:33:10"
  condition:
    hash.sha256(0, filesize) == "5b00c60a45f81997c20465d87982b3a33cae3c02ecf62240b0f56172782ed5a9"
}

rule MalwareBazaar_unknown_020_fd4fe050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4fe05051826bda9353ba88506d2394105c924e7a0aceb6300ddba4fb741e39"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 03:30:31"
  condition:
    hash.sha256(0, filesize) == "fd4fe05051826bda9353ba88506d2394105c924e7a0aceb6300ddba4fb741e39"
}

rule MalwareBazaar_unknown_021_5bdb223a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bdb223a32994f6d309e5050b5c2fc7637f377e01c423e8cfdbfbb053d3b1cba"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-09-12 03:28:15"
  condition:
    hash.sha256(0, filesize) == "5bdb223a32994f6d309e5050b5c2fc7637f377e01c423e8cfdbfbb053d3b1cba"
}

rule MalwareBazaar_unknown_022_522e81b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "522e81b62f42b1af8caf7ffec9c0e456cbe1c3a8c1c93af48ab5ea7e33fd99fc"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-09-12 03:25:41"
  condition:
    hash.sha256(0, filesize) == "522e81b62f42b1af8caf7ffec9c0e456cbe1c3a8c1c93af48ab5ea7e33fd99fc"
}

rule MalwareBazaar_unknown_023_7f2e753a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f2e753ab938a58b8807bd0ef7fb8d42a7de0c0e74012924729093c3a87a4a2e"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-09-12 03:25:40"
  condition:
    hash.sha256(0, filesize) == "7f2e753ab938a58b8807bd0ef7fb8d42a7de0c0e74012924729093c3a87a4a2e"
}

rule MalwareBazaar_unknown_024_99ac4893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ac4893f2aa8767f32701a4cc7d90a3914ae118ce029e59ada6979a7ca83d60"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-12 03:13:12"
  condition:
    hash.sha256(0, filesize) == "99ac4893f2aa8767f32701a4cc7d90a3914ae118ce029e59ada6979a7ca83d60"
}

rule MalwareBazaar_unknown_025_3a1e08b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a1e08b453d00775fdba4e4064d9ee3653958d2b64fad3c35e2d0f4ce09fb88c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-12 02:55:10"
  condition:
    hash.sha256(0, filesize) == "3a1e08b453d00775fdba4e4064d9ee3653958d2b64fad3c35e2d0f4ce09fb88c"
}

rule MalwareBazaar_unknown_026_bdd9063f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdd9063fedf9dcc2feecff5bf0123af411301b41d0999ebfd34b012b89027ea7"
    family = "unknown"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-09-12 02:47:32"
  condition:
    hash.sha256(0, filesize) == "bdd9063fedf9dcc2feecff5bf0123af411301b41d0999ebfd34b012b89027ea7"
}

rule MalwareBazaar_unknown_027_3f3dfec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f3dfec9e1345afd818fd278d087dcc94be257c82094c981bb2e881c219a3e90"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-09-12 02:46:26"
  condition:
    hash.sha256(0, filesize) == "3f3dfec9e1345afd818fd278d087dcc94be257c82094c981bb2e881c219a3e90"
}

rule MalwareBazaar_unknown_028_cc511dd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc511dd39249378019f395fba5a1869dd37d313010b7770f2f279ce0d17dddc7"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-12 02:39:00"
  condition:
    hash.sha256(0, filesize) == "cc511dd39249378019f395fba5a1869dd37d313010b7770f2f279ce0d17dddc7"
}

rule MalwareBazaar_unknown_029_7d86501f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d86501fcd6856efe97f82469500fb2e92f2bc59ceae5aa5589e943550738db9"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-09-12 02:14:28"
  condition:
    hash.sha256(0, filesize) == "7d86501fcd6856efe97f82469500fb2e92f2bc59ceae5aa5589e943550738db9"
}

rule MalwareBazaar_unknown_030_8b139961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b1399615679c18fdd9bf4cf9f90ad4929e4b3fd69af2991f12a8d304afa2c00"
    family = "unknown"
    file_name = "Request for Quote PR No 164.js"
    file_type = "js"
    first_seen = "2026-09-12 01:47:13"
  condition:
    hash.sha256(0, filesize) == "8b1399615679c18fdd9bf4cf9f90ad4929e4b3fd69af2991f12a8d304afa2c00"
}

rule MalwareBazaar_unknown_031_611452d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103"
    family = "unknown"
    file_name = "611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103.bin"
    file_type = "exe"
    first_seen = "2026-09-12 01:25:19"
  condition:
    hash.sha256(0, filesize) == "611452d6c49d83db23602b9970923fe6b9af73502ccfedfc1ab03672d2e9a103"
}

rule MalwareBazaar_unknown_032_202d6cbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c"
    family = "unknown"
    file_name = "202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c.bin"
    file_type = "exe"
    first_seen = "2026-09-12 01:25:16"
  condition:
    hash.sha256(0, filesize) == "202d6cbb3d1c1f639d388b7bcc6c3f24566eb27f2d5e7fc6520b454e5f868d2c"
}

rule MalwareBazaar_Mirai_033_999ceeda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "999ceeda77c4552adb04e486f8771daea56a99e9642e1e4510b7e985a3684d89"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-12 00:10:25"
  condition:
    hash.sha256(0, filesize) == "999ceeda77c4552adb04e486f8771daea56a99e9642e1e4510b7e985a3684d89"
}

rule MalwareBazaar_unknown_034_dbb1e585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c"
    family = "unknown"
    file_name = "dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c.bin"
    file_type = "elf"
    first_seen = "2026-09-12 00:08:29"
  condition:
    hash.sha256(0, filesize) == "dbb1e585efe9bb66f33b50181946f7f0fefcd7fce76c52c3fe84684ba915c78c"
}

rule MalwareBazaar_unknown_035_00191bd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9"
    family = "unknown"
    file_name = "00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9.bin"
    file_type = "unknown"
    first_seen = "2026-09-12 00:08:11"
  condition:
    hash.sha256(0, filesize) == "00191bd7f825efdad8517fc426ad9fb3a7db18bc305a08285f516ebe6d811ae9"
}

rule MalwareBazaar_unknown_036_28e5195b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28e5195b66174575e878e4f48132ef8589a22d8cc8533229f15ea1f96de2ce2a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 23:46:32"
  condition:
    hash.sha256(0, filesize) == "28e5195b66174575e878e4f48132ef8589a22d8cc8533229f15ea1f96de2ce2a"
}

rule MalwareBazaar_ConnectWise_037_2324697b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9"
    family = "ConnectWise"
    file_name = "2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9.msi"
    file_type = "msi"
    first_seen = "2026-09-11 23:25:15"
  condition:
    hash.sha256(0, filesize) == "2324697b8f4009e60b48753c8052f944e44232175a6e79eebb6233761e3d10f9"
}

rule MalwareBazaar_unknown_038_7ef02672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ef0267249971de2a5664d4667130f912ed4880fa399a587bba2c23fe87fba2c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 23:13:19"
  condition:
    hash.sha256(0, filesize) == "7ef0267249971de2a5664d4667130f912ed4880fa399a587bba2c23fe87fba2c"
}

rule MalwareBazaar_unknown_039_d6bdad8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6bdad8b255a82c22b6b94b818f2a044a33edff0d52224bb79cfad1faf700c0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 23:13:10"
  condition:
    hash.sha256(0, filesize) == "d6bdad8b255a82c22b6b94b818f2a044a33edff0d52224bb79cfad1faf700c0e"
}

rule MalwareBazaar_unknown_040_f75119b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75119b46828e699a35b12230d66f34ce0bd9fe0e79edc9317912e2446ebbff4"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-09-11 23:07:15"
  condition:
    hash.sha256(0, filesize) == "f75119b46828e699a35b12230d66f34ce0bd9fe0e79edc9317912e2446ebbff4"
}

rule MalwareBazaar_Mirai_041_8ab302b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ab302b2e0fa873555d95673939b59ca2d4293b6fea338b6c074472cd1ca2333"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-09-11 23:04:38"
  condition:
    hash.sha256(0, filesize) == "8ab302b2e0fa873555d95673939b59ca2d4293b6fea338b6c074472cd1ca2333"
}

rule MalwareBazaar_unknown_042_041bf995
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "041bf99578bc1c3679f0fac99eeff3ed0eee3913ba462b21e1accd1d07106839"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:58:24"
  condition:
    hash.sha256(0, filesize) == "041bf99578bc1c3679f0fac99eeff3ed0eee3913ba462b21e1accd1d07106839"
}

rule MalwareBazaar_unknown_043_26a618a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a618a76ddc78275deeeda1f76c77c8311a3027aaf54b0dd954c046c2347ad9"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-09-11 22:50:16"
  condition:
    hash.sha256(0, filesize) == "26a618a76ddc78275deeeda1f76c77c8311a3027aaf54b0dd954c046c2347ad9"
}

rule MalwareBazaar_unknown_044_377379c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "377379c652f12ac35cbdbcbd670049127d975fa53968403c1c71b829320f5415"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 22:49:08"
  condition:
    hash.sha256(0, filesize) == "377379c652f12ac35cbdbcbd670049127d975fa53968403c1c71b829320f5415"
}

rule MalwareBazaar_SimpleHelp_045_42e9c10c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42e9c10c1da5c624010da51c0654bfe027e71d175ac7bfcb695608cf01a8a6ca"
    family = "SimpleHelp"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 22:39:51"
  condition:
    hash.sha256(0, filesize) == "42e9c10c1da5c624010da51c0654bfe027e71d175ac7bfcb695608cf01a8a6ca"
}

rule MalwareBazaar_unknown_046_872084e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872084e1b23f76e71344d173ba0db5a74937e47be5fa1300c63b95ddac532962"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 22:33:13"
  condition:
    hash.sha256(0, filesize) == "872084e1b23f76e71344d173ba0db5a74937e47be5fa1300c63b95ddac532962"
}

rule MalwareBazaar_unknown_047_3102c7b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3102c7b291c9c10cda2e3e7901fb66940a98bb75ca0d728a694787db57b76b39"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-09-11 22:32:06"
  condition:
    hash.sha256(0, filesize) == "3102c7b291c9c10cda2e3e7901fb66940a98bb75ca0d728a694787db57b76b39"
}

rule MalwareBazaar_unknown_048_0f30e222
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f30e22204e82249862c49a460537062d2e6a86251e5ba7c8c76d2751310c0d2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 22:20:26"
  condition:
    hash.sha256(0, filesize) == "0f30e22204e82249862c49a460537062d2e6a86251e5ba7c8c76d2751310c0d2"
}

rule MalwareBazaar_Mirai_049_289eba02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "289eba021664d56c712b0fe24c3405101648fc158a35073e8e167a048cf9ba34"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-11 22:19:42"
  condition:
    hash.sha256(0, filesize) == "289eba021664d56c712b0fe24c3405101648fc158a35073e8e167a048cf9ba34"
}

rule MalwareBazaar_Mirai_050_7e1ae536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1ae53631f43638bbfe0596aa871163b1cb0227f2ff49628b460082ff9e318a"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-11 22:18:30"
  condition:
    hash.sha256(0, filesize) == "7e1ae53631f43638bbfe0596aa871163b1cb0227f2ff49628b460082ff9e318a"
}

rule MalwareBazaar_unknown_051_2b162afc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b162afcac93c8522f3ea60ce95b8f00eef7572e6a26e9bc66e9d37314b2c07b"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-09-11 22:16:16"
  condition:
    hash.sha256(0, filesize) == "2b162afcac93c8522f3ea60ce95b8f00eef7572e6a26e9bc66e9d37314b2c07b"
}

rule MalwareBazaar_unknown_052_8ddb90d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddb90d70c6eb79c031f14c269cbc26a9c0b9733b97d37dc816935fbc195b68c"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-09-11 22:13:39"
  condition:
    hash.sha256(0, filesize) == "8ddb90d70c6eb79c031f14c269cbc26a9c0b9733b97d37dc816935fbc195b68c"
}

rule MalwareBazaar_Mirai_053_075bc807
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "075bc80720bfb2176c2ca8802dd8e3c516b5b7bacc666a57d0c0f05749059867"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-11 22:11:23"
  condition:
    hash.sha256(0, filesize) == "075bc80720bfb2176c2ca8802dd8e3c516b5b7bacc666a57d0c0f05749059867"
}

rule MalwareBazaar_ValleyRAT_054_8b4664c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b4664c393c78d5e5cb22b6f95afd9ed70751b56a8593c53aa8626c5116e0783"
    family = "ValleyRAT"
    file_name = "资源_版本_图标_4419.exe"
    file_type = "exe"
    first_seen = "2026-09-11 22:10:21"
  condition:
    hash.sha256(0, filesize) == "8b4664c393c78d5e5cb22b6f95afd9ed70751b56a8593c53aa8626c5116e0783"
}

rule MalwareBazaar_unknown_055_d1b852aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b852aad9b9f623010dcfe1ab3ee3eb125dc6d9dafcd26e93ac8fe59d13a4fd"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:10:15"
  condition:
    hash.sha256(0, filesize) == "d1b852aad9b9f623010dcfe1ab3ee3eb125dc6d9dafcd26e93ac8fe59d13a4fd"
}

rule MalwareBazaar_ValleyRAT_056_92d7268d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92d7268dd1d01a365834bfaaee3d2f30f477dd997fdc747a009438a16040d814"
    family = "ValleyRAT"
    file_name = "2026.09.11裁员名单及补偿方案WPS.exe"
    file_type = "exe"
    first_seen = "2026-09-11 22:09:20"
  condition:
    hash.sha256(0, filesize) == "92d7268dd1d01a365834bfaaee3d2f30f477dd997fdc747a009438a16040d814"
}

rule MalwareBazaar_unknown_057_2e8e8593
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e8e8593bab13ebceb50cb1905f1c78d96c8fa5eee3cfb1fef5e8e9cc2d35bba"
    family = "unknown"
    file_name = "2026.09.11....人 员 名 单 LF.exe"
    file_type = "exe"
    first_seen = "2026-09-11 22:07:58"
  condition:
    hash.sha256(0, filesize) == "2e8e8593bab13ebceb50cb1905f1c78d96c8fa5eee3cfb1fef5e8e9cc2d35bba"
}

rule MalwareBazaar_Mirai_058_8ecfb243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ecfb2433de0daff367218bcfcc8948208dd638409f84d1a3ebec384ef0954ee"
    family = "Mirai"
    file_name = "bot.ppc"
    file_type = "elf"
    first_seen = "2026-09-11 22:07:38"
  condition:
    hash.sha256(0, filesize) == "8ecfb2433de0daff367218bcfcc8948208dd638409f84d1a3ebec384ef0954ee"
}

rule MalwareBazaar_Mirai_059_006037c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "006037c0aaf9e99318842e41057f4f47092ba8dbbd4f7d24ad0f7684a895ac3f"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-09-11 22:07:35"
  condition:
    hash.sha256(0, filesize) == "006037c0aaf9e99318842e41057f4f47092ba8dbbd4f7d24ad0f7684a895ac3f"
}

rule MalwareBazaar_unknown_060_a9e5cd6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9e5cd6b32e7f977682e529a669cf991f61764f76cabba258fd1a9391e0cdfed"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-09-11 22:07:34"
  condition:
    hash.sha256(0, filesize) == "a9e5cd6b32e7f977682e529a669cf991f61764f76cabba258fd1a9391e0cdfed"
}

rule MalwareBazaar_unknown_061_4b10df23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b10df23597ecbe7be2e660976db1dc16f6ae8965c87348f09ae94c1b63c5c08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 22:04:47"
  condition:
    hash.sha256(0, filesize) == "4b10df23597ecbe7be2e660976db1dc16f6ae8965c87348f09ae94c1b63c5c08"
}

rule MalwareBazaar_unknown_062_a3d81818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3d81818dff46b4308800261c4d762eade3580fe6cfa1b216fb93f4fe6d507da"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 22:03:15"
  condition:
    hash.sha256(0, filesize) == "a3d81818dff46b4308800261c4d762eade3580fe6cfa1b216fb93f4fe6d507da"
}

rule MalwareBazaar_unknown_063_7071105d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7071105d106dd6e6272f56d73d8868b9c025727d099c5d73bb7c56f24ace4cd0"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-09-11 22:03:13"
  condition:
    hash.sha256(0, filesize) == "7071105d106dd6e6272f56d73d8868b9c025727d099c5d73bb7c56f24ace4cd0"
}

rule MalwareBazaar_unknown_064_70cd92cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70cd92cc85d2d09088a6e771f56c024112408f8331182176abc01acb1b0d4dab"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:00:46"
  condition:
    hash.sha256(0, filesize) == "70cd92cc85d2d09088a6e771f56c024112408f8331182176abc01acb1b0d4dab"
}

rule MalwareBazaar_unknown_065_5d757e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d757e786fd27a16b5ad72055c510603fed18a91221011e20dbe6959f649af3f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 22:00:45"
  condition:
    hash.sha256(0, filesize) == "5d757e786fd27a16b5ad72055c510603fed18a91221011e20dbe6959f649af3f"
}

rule MalwareBazaar_Mirai_066_ae58a420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae58a420b0c7c35b5b56ccd413c5e0cf73935b433bc58a30d31634fb4d12fc38"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-09-11 21:59:30"
  condition:
    hash.sha256(0, filesize) == "ae58a420b0c7c35b5b56ccd413c5e0cf73935b433bc58a30d31634fb4d12fc38"
}

rule MalwareBazaar_Gh0stRAT_067_668dcf12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668dcf124501c1767d4ebc19f29cb44d6474cbff28947d63a695628f467b6345"
    family = "Gh0stRAT"
    file_name = "SuggestAssist.exe"
    file_type = "exe"
    first_seen = "2026-09-11 21:57:17"
  condition:
    hash.sha256(0, filesize) == "668dcf124501c1767d4ebc19f29cb44d6474cbff28947d63a695628f467b6345"
}

rule MalwareBazaar_Gh0stRAT_068_91dfe304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91dfe3049b9de072378178064f2a248efa13dcdc23e0b51e578a5f4378e2b827"
    family = "Gh0stRAT"
    file_name = "SuggestAssist.exe"
    file_type = "exe"
    first_seen = "2026-09-11 21:57:17"
  condition:
    hash.sha256(0, filesize) == "91dfe3049b9de072378178064f2a248efa13dcdc23e0b51e578a5f4378e2b827"
}

rule MalwareBazaar_unknown_069_1bb6d17d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bb6d17dfbb9e9f568643559f62fd66066fcf965199de062552bba2b30c37df0"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-09-11 21:56:27"
  condition:
    hash.sha256(0, filesize) == "1bb6d17dfbb9e9f568643559f62fd66066fcf965199de062552bba2b30c37df0"
}

rule MalwareBazaar_unknown_070_774a531c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774a531c6b2a7a6a10f94fcc74649dd6a20e79b7e06dae532c49e8b1fcf84c2f"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-09-11 21:53:23"
  condition:
    hash.sha256(0, filesize) == "774a531c6b2a7a6a10f94fcc74649dd6a20e79b7e06dae532c49e8b1fcf84c2f"
}

rule MalwareBazaar_unknown_071_923dbede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "923dbede92d58d7c58199c91b8f6cbdafdd938337889879e8ec366c1bf4d0577"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-09-11 21:53:22"
  condition:
    hash.sha256(0, filesize) == "923dbede92d58d7c58199c91b8f6cbdafdd938337889879e8ec366c1bf4d0577"
}

rule MalwareBazaar_unknown_072_2250189b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2250189b2c5c24f38393267d6e2a53ee7bf6068ce89dc16c27585831951d0b1f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 21:52:42"
  condition:
    hash.sha256(0, filesize) == "2250189b2c5c24f38393267d6e2a53ee7bf6068ce89dc16c27585831951d0b1f"
}

rule MalwareBazaar_unknown_073_d3d007c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3d007c14bda781264dd314938122f6c7d3b772d5870787cfbaa992d4c251c61"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-09-11 21:51:19"
  condition:
    hash.sha256(0, filesize) == "d3d007c14bda781264dd314938122f6c7d3b772d5870787cfbaa992d4c251c61"
}

rule MalwareBazaar_unknown_074_985cf05a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "985cf05a00486d49bf1047e1071c4c47c15873dc3da4bb10fc444ffe48f32e3b"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-09-11 21:48:12"
  condition:
    hash.sha256(0, filesize) == "985cf05a00486d49bf1047e1071c4c47c15873dc3da4bb10fc444ffe48f32e3b"
}

rule MalwareBazaar_unknown_075_0e604973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e604973ecdd6fc60aeeffed859f68e38217f018d6568c8270a611d82cc9dbd6"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-09-11 21:44:05"
  condition:
    hash.sha256(0, filesize) == "0e604973ecdd6fc60aeeffed859f68e38217f018d6568c8270a611d82cc9dbd6"
}

rule MalwareBazaar_unknown_076_eddf6ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eddf6ba316a60044c88ba8570d9bb0ad0ee4f91a4b017b844f5d4d42af8479bb"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-09-11 21:43:02"
  condition:
    hash.sha256(0, filesize) == "eddf6ba316a60044c88ba8570d9bb0ad0ee4f91a4b017b844f5d4d42af8479bb"
}

rule MalwareBazaar_unknown_077_0859c524
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd"
    family = "unknown"
    file_name = "0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd.exe"
    file_type = "exe"
    first_seen = "2026-09-11 21:39:36"
  condition:
    hash.sha256(0, filesize) == "0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd"
}

rule MalwareBazaar_Mirai_078_e9704311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9704311b60ac9400afb5819e273ccccc2093321c239610952e8f526c4388c66"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-09-11 21:35:24"
  condition:
    hash.sha256(0, filesize) == "e9704311b60ac9400afb5819e273ccccc2093321c239610952e8f526c4388c66"
}

rule MalwareBazaar_unknown_079_0463f45c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0463f45c75df9cedca6f373b259715888bf4696ec78f629ec3b2998a3036021e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 21:35:22"
  condition:
    hash.sha256(0, filesize) == "0463f45c75df9cedca6f373b259715888bf4696ec78f629ec3b2998a3036021e"
}

rule MalwareBazaar_unknown_080_620bf856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620bf856545ecf108abad84aeea7eb41d96667a2c6412810fabbee2e8ef08144"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 21:27:14"
  condition:
    hash.sha256(0, filesize) == "620bf856545ecf108abad84aeea7eb41d96667a2c6412810fabbee2e8ef08144"
}

rule MalwareBazaar_unknown_081_80957b43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80957b43a59cc8eb7fd66ba361edc8bbefa45e1d5e8d64de8e043f430e01320d"
    family = "unknown"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-09-11 21:24:09"
  condition:
    hash.sha256(0, filesize) == "80957b43a59cc8eb7fd66ba361edc8bbefa45e1d5e8d64de8e043f430e01320d"
}

rule MalwareBazaar_unknown_082_3f8a2697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f8a269735332db54cef58223415138998c4201b84d8269cdf6f2c3f862b10bd"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-09-11 21:24:08"
  condition:
    hash.sha256(0, filesize) == "3f8a269735332db54cef58223415138998c4201b84d8269cdf6f2c3f862b10bd"
}

rule MalwareBazaar_unknown_083_c8fd1ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8fd1ce67cac8f8bf4f2ced77f82cca4ddcc3ab084040898776e30c962c055ff"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-09-11 21:24:07"
  condition:
    hash.sha256(0, filesize) == "c8fd1ce67cac8f8bf4f2ced77f82cca4ddcc3ab084040898776e30c962c055ff"
}

rule MalwareBazaar_unknown_084_36c8e66b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36c8e66b56a21a7a9d30ecde90d096d037c8e30a0596a66ddf30fa221a0bbc96"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-09-11 21:13:11"
  condition:
    hash.sha256(0, filesize) == "36c8e66b56a21a7a9d30ecde90d096d037c8e30a0596a66ddf30fa221a0bbc96"
}

rule MalwareBazaar_unknown_085_d7930ec3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7930ec34b23b972555b6ccd5ea1c333a04631b791f54820c5b9df8f11bddd3d"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-09-11 21:05:06"
  condition:
    hash.sha256(0, filesize) == "d7930ec34b23b972555b6ccd5ea1c333a04631b791f54820c5b9df8f11bddd3d"
}

rule MalwareBazaar_unknown_086_4a84d211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e"
    family = "unknown"
    file_name = "4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e.sh"
    file_type = "sh"
    first_seen = "2026-09-11 20:47:01"
  condition:
    hash.sha256(0, filesize) == "4a84d21194b584be67bebb9268e5f8cde55b65b51f81050cd16740548ee0e66e"
}

rule MalwareBazaar_unknown_087_135764ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135764ae4337fbf9f8bc3119f6f83eebfc8df847a3fd2f33f25e0ded54f7dc46"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-09-11 20:25:04"
  condition:
    hash.sha256(0, filesize) == "135764ae4337fbf9f8bc3119f6f83eebfc8df847a3fd2f33f25e0ded54f7dc46"
}

rule MalwareBazaar_unknown_088_681ed8e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8"
    family = "unknown"
    file_name = "681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8.sh"
    file_type = "sh"
    first_seen = "2026-09-11 20:24:02"
  condition:
    hash.sha256(0, filesize) == "681ed8e2061fda8b31031a8d534b01ce53e1634913fe04e696c6183282f6e5c8"
}

rule MalwareBazaar_unknown_089_dbac8628
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbac862805f4b4e1b426ed441bf4c4d2c9523ef17189759294f2d3cfeb88e9a2"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-11 20:09:08"
  condition:
    hash.sha256(0, filesize) == "dbac862805f4b4e1b426ed441bf4c4d2c9523ef17189759294f2d3cfeb88e9a2"
}

rule MalwareBazaar_RemusStealer_090_ca3ebe2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca3ebe2ce77f73faf246331eff19f8c33966520ff7c3369d83d244dfdbda0a1a"
    family = "RemusStealer"
    file_name = "Real Executor.exe"
    file_type = "exe"
    first_seen = "2026-09-11 19:46:20"
  condition:
    hash.sha256(0, filesize) == "ca3ebe2ce77f73faf246331eff19f8c33966520ff7c3369d83d244dfdbda0a1a"
}

rule MalwareBazaar_ConnectWise_091_a36ee55b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a36ee55b824760641e9c06a8b30fc2ed23851bc49da254c61a68fdcf4b192bf0"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.msi"
    file_type = "msi"
    first_seen = "2026-09-11 19:44:05"
  condition:
    hash.sha256(0, filesize) == "a36ee55b824760641e9c06a8b30fc2ed23851bc49da254c61a68fdcf4b192bf0"
}

rule MalwareBazaar_unknown_092_9654e2f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e"
    family = "unknown"
    file_name = "9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e.sh"
    file_type = "sh"
    first_seen = "2026-09-11 19:41:10"
  condition:
    hash.sha256(0, filesize) == "9654e2f8add456b4c77d2435ed30299fd9c0935ae6ce34adc52833926e400e6e"
}

rule MalwareBazaar_unknown_093_9e725f48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e725f4893d50fccea212a96359489cb36a00e8f397ebbb2e712278b124c5567"
    family = "unknown"
    file_name = "Bootstrler_v31.0.534.exe"
    file_type = "exe"
    first_seen = "2026-09-11 19:40:17"
  condition:
    hash.sha256(0, filesize) == "9e725f4893d50fccea212a96359489cb36a00e8f397ebbb2e712278b124c5567"
}

rule MalwareBazaar_ConnectWise_094_db3cf6da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3cf6dae0646bbe3715d66efb5efdc0a42c96efbbe4166e043d890a1a74c2db"
    family = "ConnectWise"
    file_name = "Installer.msi"
    file_type = "msi"
    first_seen = "2026-09-11 19:36:49"
  condition:
    hash.sha256(0, filesize) == "db3cf6dae0646bbe3715d66efb5efdc0a42c96efbbe4166e043d890a1a74c2db"
}

rule MalwareBazaar_ConnectWise_095_1ba8c6b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ba8c6b1a58b294eb15e4f846b141fdda793f834e340767515d89609de5802ad"
    family = "ConnectWise"
    file_name = "E-Invite.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 19:32:33"
  condition:
    hash.sha256(0, filesize) == "1ba8c6b1a58b294eb15e4f846b141fdda793f834e340767515d89609de5802ad"
}

rule MalwareBazaar_ConnectWise_096_7583a696
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7583a696c82d66041cf8778d18c99ebc142dafde43f37fbe5dd088af6cad0fe8"
    family = "ConnectWise"
    file_name = "E-Invite.iso"
    file_type = "iso"
    first_seen = "2026-09-11 19:32:20"
  condition:
    hash.sha256(0, filesize) == "7583a696c82d66041cf8778d18c99ebc142dafde43f37fbe5dd088af6cad0fe8"
}

rule MalwareBazaar_unknown_097_1ecf72ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ecf72ad88cb8cda3263dcd384dc4a460d2339b3f79d352d20050ebf07cf7310"
    family = "unknown"
    file_name = "Frostix.exe"
    file_type = "exe"
    first_seen = "2026-09-11 19:29:37"
  condition:
    hash.sha256(0, filesize) == "1ecf72ad88cb8cda3263dcd384dc4a460d2339b3f79d352d20050ebf07cf7310"
}

rule MalwareBazaar_unknown_098_17052839
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1705283904501e94a2573166083e76aa90adb98d647cfe30769ea1948805f086"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 19:22:16"
  condition:
    hash.sha256(0, filesize) == "1705283904501e94a2573166083e76aa90adb98d647cfe30769ea1948805f086"
}

rule MalwareBazaar_GoToResolve_099_d73ee5f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d73ee5f1b3855f67fa6e09a0ff4a288d27349902123625c89aa0caf22427af8a"
    family = "GoToResolve"
    file_name = "crm.msi"
    file_type = "msi"
    first_seen = "2026-09-11 19:21:13"
  condition:
    hash.sha256(0, filesize) == "d73ee5f1b3855f67fa6e09a0ff4a288d27349902123625c89aa0caf22427af8a"
}

rule MalwareBazaar_GoToResolve_100_e68f2fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e68f2fd161378cad6e3a51312b21a87971851d59a59257be6b4f8a868cc18569"
    family = "GoToResolve"
    file_name = "ivCardco.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 19:20:31"
  condition:
    hash.sha256(0, filesize) == "e68f2fd161378cad6e3a51312b21a87971851d59a59257be6b4f8a868cc18569"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

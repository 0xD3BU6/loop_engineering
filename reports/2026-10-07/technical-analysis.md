# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-07

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 673 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 673 |
| Unique family labels | 9 |
| Unique file types | 16 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 55 |
| Mirai | 33 |
| Gafgyt | 5 |
| NetSupport | 2 |
| PureLogsStealer | 1 |
| Formbook | 1 |
| WannaCry | 1 |
| AgentTesla | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 40 |
| exe | 27 |
| macho | 5 |
| ps1 | 5 |
| hta | 4 |
| zip | 4 |
| js | 4 |
| sh | 3 |
| dll | 1 |
| a3x | 1 |

## Per-Sample Analysis

### Sample 1: `2d439ae8d04b35e4`

| Field | Value |
|---|---|
| SHA-256 | `2d439ae8d04b35e424c39632d77c9ceb096a1c0f935d07aea9fbfab18b67c151` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm7` |
| File type | `elf` |
| First seen | `2026-10-07 06:04:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c97382f4a525b45f6736d953ef6a808` |
| SHA-1 | `fb965b2e2f39d0a334ee945aa7ddd5200e627ac1` |
| SHA-256 | `2d439ae8d04b35e424c39632d77c9ceb096a1c0f935d07aea9fbfab18b67c151` |
| SHA3-384 | `edd174a8f4a9df8dff25fd5b73d9a4a70d52d3803f13fa52566b04585ffdb11dde5921ffb557cbaae9e6f4b553c3a5e6` |
| TLSH | `T1E0F3F846B9829F15D5C722FEFA9F415833536BACE3EE7102D9205F6023CA69B0B63152` |
| TELFHASH | `t166d097010c1811f462a9024082af031ecd66a0ab130c4423d2d627ec9fc3382340a807` |
| SSDEEP | `3072:7OwkkgGVzE95rlCtNfoQAo0hP4MHu0aVQHOCawxGJA+UetGVC:7s6NffANhPpO0aVQHOCaiR+FtGVC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_2d439ae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d439ae8d04b35e424c39632d77c9ceb096a1c0f935d07aea9fbfab18b67c151"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-10-07 06:04:11"
  condition:
    hash.sha256(0, filesize) == "2d439ae8d04b35e424c39632d77c9ceb096a1c0f935d07aea9fbfab18b67c151"
}
```

### Sample 2: `a9a97675dd4fd2ca`

| Field | Value |
|---|---|
| SHA-256 | `a9a97675dd4fd2cad9b66f31c0bb3cf177cfbe40f29a664abce74b11da645984` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-07 05:48:20` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30ddf81994d4d81feb012f1419bcab53` |
| SHA-1 | `19e62a6656a739f189d7b3ed9347a860e07ffb11` |
| SHA-256 | `a9a97675dd4fd2cad9b66f31c0bb3cf177cfbe40f29a664abce74b11da645984` |
| SHA3-384 | `1bf3722b1b85d6191a82c036510f72722135f56eab28fb73b3faa34ae7095a4449553155ca2bcd08f4a1e9bbd7020a76` |
| IMPHASH | `6f6a2d13c671ec1552810ff82e0b59e6` |
| TLSH | `T1C0D4AF12B5A1D476E1724635CC64EB549B7DBC700B209BCB63C00AEA6E716C0AF37B67` |
| SSDEEP | `12288:PYxFyPpxZjtDRvNNq6E+xthsAEnyxBlDetAqxSvkkKofgK:PY+PjHRlNhhDh/Enybs7of` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_a9a97675
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a97675dd4fd2cad9b66f31c0bb3cf177cfbe40f29a664abce74b11da645984"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 05:48:20"
  condition:
    hash.sha256(0, filesize) == "a9a97675dd4fd2cad9b66f31c0bb3cf177cfbe40f29a664abce74b11da645984"
}
```

### Sample 3: `19faee0d47e5ba75`

| Field | Value |
|---|---|
| SHA-256 | `19faee0d47e5ba75566c00afc5e6e64a29744ca6f366c32c0d22acd147773e00` |
| Family label | `unknown` |
| File name | `ppc64le` |
| File type | `elf` |
| First seen | `2026-10-07 05:33:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a995bfd63ea67dd72b3139538657341f` |
| SHA-1 | `6b26de04032472826d9bf0e51cf0a0a654f2fb59` |
| SHA-256 | `19faee0d47e5ba75566c00afc5e6e64a29744ca6f366c32c0d22acd147773e00` |
| SHA3-384 | `ac357b3e8119ee4c266e8f5616dfcae0959cb488875f99db55be52864dbfe9041c8ed7a7339d5c5c3d57203ba782766a` |
| TLSH | `T1D9563A43EA096F95C9204D3785B74D9127626D986B3187439B08F3BFBCB73064B26F98` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:aiP8PmPhV3qswBm0t+WZMMZbgtJK9/b8m8IHUJp5OVOqY0v5vlE7:aiP8yaswBm0t+WZMObiJK9/b8m8IHUJb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_19faee0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19faee0d47e5ba75566c00afc5e6e64a29744ca6f366c32c0d22acd147773e00"
    family = "unknown"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-10-07 05:33:34"
  condition:
    hash.sha256(0, filesize) == "19faee0d47e5ba75566c00afc5e6e64a29744ca6f366c32c0d22acd147773e00"
}
```

### Sample 4: `618a1b1d30d6f2bd`

| Field | Value |
|---|---|
| SHA-256 | `618a1b1d30d6f2bd4a2a122c6caa7cada264460175e4c41a9a7ab39d17b466b3` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-07 05:13:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0f4559fb651ecdc6bf0eda7639398c8` |
| SHA-1 | `da7bcac0fbe55d063da665bd0d71d9f5858b5980` |
| SHA-256 | `618a1b1d30d6f2bd4a2a122c6caa7cada264460175e4c41a9a7ab39d17b466b3` |
| SHA3-384 | `03a2429bab01f83db7851df8f44cf5bc9d70a8cf9fcc7b2e5cf1f2c2225bf7916376b216bf583e8c0687ceccf6914108` |
| TLSH | `T169B58E44A64D682AEAC6F0FDCD4C08F0731F34E41514D3BA3C25A159ED86BE58B7AB72` |
| SSDEEP | `24576:FOSC1gzsOrjZWj3qVzSNHJAiDp5xOmPrzw/bL+HaGVJwCBM+t1cMD0sYLXKk5:FT4gzswjhVCXJiL+d/7zBN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_618a1b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618a1b1d30d6f2bd4a2a122c6caa7cada264460175e4c41a9a7ab39d17b466b3"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-07 05:13:24"
  condition:
    hash.sha256(0, filesize) == "618a1b1d30d6f2bd4a2a122c6caa7cada264460175e4c41a9a7ab39d17b466b3"
}
```

### Sample 5: `3740e3883b648404`

| Field | Value |
|---|---|
| SHA-256 | `3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538` |
| Family label | `unknown` |
| File name | `3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538` |
| File type | `macho` |
| First seen | `2026-10-07 05:12:59` |
| Reporter | `anonymous` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9705d01e2370f9170178b848ff74528e` |
| SHA-1 | `1de60ec944e2d0720ceab5c49299c1185d94fb27` |
| SHA-256 | `3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538` |
| SHA3-384 | `a8b43442b9afe14ba7017850f4d2c31a16632d1dca05be06cc2d58fcef161be47994cebfe6e081d966311dbd5b082ac3` |
| TLSH | `T12274E117D12904D6EC38D3745DA66FF2E238BE2016680BAD7E546A343E72B1A7509F23` |
| SSDEEP | `6144:A9PiVVP/U1GMk0jC7ZjOWiVVPpUhGMsolC:A9aDP/7/7szDPppT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_3740e388
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538"
    family = "unknown"
    file_name = "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538"
    file_type = "macho"
    first_seen = "2026-10-07 05:12:59"
  condition:
    hash.sha256(0, filesize) == "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538"
}
```

### Sample 6: `c4c7cc2f8e281b36`

| Field | Value |
|---|---|
| SHA-256 | `c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5` |
| Family label | `unknown` |
| File name | `c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5` |
| File type | `macho` |
| First seen | `2026-10-07 05:12:39` |
| Reporter | `anonymous` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fe10e128dae844ed9f869bb94bef395` |
| SHA-1 | `24e65e0e0a2cc2d0c216577639361dcee99fd3f7` |
| SHA-256 | `c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5` |
| SHA3-384 | `241b924403c0140477eba1572f4c9bf5f2185b83fee4cbaf55e92bcc84c1d289a9c96c6f2c2f440138a6aa10f71fcb81` |
| TLSH | `T1CEE3D027D23642F5DC2483749CB67FF6E138BD612A2C0E5DB7946B213A237197848B63` |
| SSDEEP | `3072:4UNp7cWK62erHz3Vi4+6yPyaU16JUDim1omEPAPs9O+KQT7:h9PiVVP/U1GMk0jC7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_c4c7cc2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5"
    family = "unknown"
    file_name = "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5"
    file_type = "macho"
    first_seen = "2026-10-07 05:12:39"
  condition:
    hash.sha256(0, filesize) == "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5"
}
```

### Sample 7: `92e56ff0e46fb9e5`

| Field | Value |
|---|---|
| SHA-256 | `92e56ff0e46fb9e52f8866bbf4e5c1c1e989a13377aa6dcc9079a8adcdaa4bc9` |
| Family label | `Mirai` |
| File name | `bash` |
| File type | `elf` |
| First seen | `2026-10-07 05:03:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06d87f600722ae93583c12965f4a1fd4` |
| SHA-1 | `16c2f8ac8096e089a1e3dd86a146cbcc42f3e83b` |
| SHA-256 | `92e56ff0e46fb9e52f8866bbf4e5c1c1e989a13377aa6dcc9079a8adcdaa4bc9` |
| SHA3-384 | `cc36c6c993874c81444349c54701a47f814f863abfd32fc757db1f5d09a1540b98097d937adf66480c9a1c920fba6d45` |
| TLSH | `T1D2B33ACDE740D577D58319B2D29787234072EA361A1ACA05F3DBFCB4AB25184B221BED` |
| TELFHASH | `t136213542627d8e297fb24924acac07f11956152372407f70ff5ec1c4653b009b575d8f` |
| SSDEEP | `3072:YHS9r0UVKOtvsad4m3KkXP+1ZBHDaSo4XRZhSvn:9KOtvPxKC+LBHDaSo4XRZhSvn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_92e56ff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92e56ff0e46fb9e52f8866bbf4e5c1c1e989a13377aa6dcc9079a8adcdaa4bc9"
    family = "Mirai"
    file_name = "bash"
    file_type = "elf"
    first_seen = "2026-10-07 05:03:26"
  condition:
    hash.sha256(0, filesize) == "92e56ff0e46fb9e52f8866bbf4e5c1c1e989a13377aa6dcc9079a8adcdaa4bc9"
}
```

### Sample 8: `040a0da5c3f26dc1`

| Field | Value |
|---|---|
| SHA-256 | `040a0da5c3f26dc1b971271e13e8930c7680b8aeef8aba87f885009760a71709` |
| Family label | `unknown` |
| File name | `beacon_x` |
| File type | `elf` |
| First seen | `2026-10-07 04:46:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e839e368326a7d8d040ca367cfeca2b` |
| SHA-1 | `4f46934c931fde7b444ed379a05c7312c1a1d874` |
| SHA-256 | `040a0da5c3f26dc1b971271e13e8930c7680b8aeef8aba87f885009760a71709` |
| SHA3-384 | `a66d7666dfa7c3020f6bd4c40e005a899818eccd6f356f9f5956fd9ea420df650636c9dd280d62015fd3e67a08c4c0b0` |
| TLSH | `T1DE565A43ECA555E8C0A9E2308A629253BB717C885F3123D33B90F7782F76BD06AB5754` |
| TELFHASH | `t139327b744dbd38b4b699d911b3a3b4b4957719a572f838f11463a980ffc1e802ce283b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:R8NRpSxmtd4mHFzSfRc1DJU3DCEYCxx9r4v13v+GwsMDoqaVwDasVU1MJlemXE1V:R8UAztBCp9g133Mc/sZE1kSZHOpE5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_040a0da5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040a0da5c3f26dc1b971271e13e8930c7680b8aeef8aba87f885009760a71709"
    family = "unknown"
    file_name = "beacon_x"
    file_type = "elf"
    first_seen = "2026-10-07 04:46:22"
  condition:
    hash.sha256(0, filesize) == "040a0da5c3f26dc1b971271e13e8930c7680b8aeef8aba87f885009760a71709"
}
```

### Sample 9: `a45e7396cd5e64cf`

| Field | Value |
|---|---|
| SHA-256 | `a45e7396cd5e64cf9ea7567f0e8d56d4a41c4b1b168981f8f0fb33e7e2a3dce5` |
| Family label | `Mirai` |
| File name | `5r3fqt67ew531has4231.arm` |
| File type | `elf` |
| First seen | `2026-10-07 04:46:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27c6dacc56d653e983342df7b2efc145` |
| SHA-1 | `9927374ad0144cec8f0e2dece691570b78a344ed` |
| SHA-256 | `a45e7396cd5e64cf9ea7567f0e8d56d4a41c4b1b168981f8f0fb33e7e2a3dce5` |
| SHA3-384 | `17a04bcffc53afcf29d059772b4b32658376fd1bc4eccb737565d6c529306eb45f87d7329cd616328e90391989683349` |
| TLSH | `T1C4933A85FD815A22C6C513B7FA2E028D372253E8D2EF7103ED216F257ACA81B0D77A55` |
| TELFHASH | `t19401446b83a60dec97d847d5918c7011f3bd75925666356200cecf0fc1931e2f0b9824` |
| SSDEEP | `1536:dvfKox9gBrYOnJ5F9w68KE9705qpzmge2a5p5Qyd7dbvKlmCoEhTWvFpCvTwbZnj:dvfKdYa6sLcO2YpNhbilvCy7wbZnj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_a45e7396
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a45e7396cd5e64cf9ea7567f0e8d56d4a41c4b1b168981f8f0fb33e7e2a3dce5"
    family = "Mirai"
    file_name = "5r3fqt67ew531has4231.arm"
    file_type = "elf"
    first_seen = "2026-10-07 04:46:18"
  condition:
    hash.sha256(0, filesize) == "a45e7396cd5e64cf9ea7567f0e8d56d4a41c4b1b168981f8f0fb33e7e2a3dce5"
}
```

### Sample 10: `965e3c0a85daa83a`

| Field | Value |
|---|---|
| SHA-256 | `965e3c0a85daa83a38e5841a77fad2407f42b28870ccab3f48efb7999c424127` |
| Family label | `Gafgyt` |
| File name | `dissx86` |
| File type | `elf` |
| First seen | `2026-10-07 04:37:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc8e8e1cc3e7e95a862d0aedae57edb7` |
| SHA-1 | `be5049d292035d40c4e0176270fe69e156e1cdb2` |
| SHA-256 | `965e3c0a85daa83a38e5841a77fad2407f42b28870ccab3f48efb7999c424127` |
| SHA3-384 | `ef4d4788a1575f931e36bf25a8792d4f715a63d935def088cf7c5da6d0621248c5f8e48109412d44e7effa57aeeddf1f` |
| TLSH | `T149346B1775E0C9FBC4C7E7B46BDB81625932F4391B32610B73A4BDA62F1DAD8A90C211` |
| TELFHASH | `t180611105a43d09d9de231c196c686ff35957e62a32e6bb29ff1addc0084e429f158e0f` |
| SSDEEP | `6144:Yy41/gVOG9RFdpDC8YwQRibGovsKZ0eLjLDJn2UkJpO:z414VOOFyHwQqXvsKZ0eLjLDJn2UkJpO` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_010_965e3c0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965e3c0a85daa83a38e5841a77fad2407f42b28870ccab3f48efb7999c424127"
    family = "Gafgyt"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-07 04:37:25"
  condition:
    hash.sha256(0, filesize) == "965e3c0a85daa83a38e5841a77fad2407f42b28870ccab3f48efb7999c424127"
}
```

### Sample 11: `d292f68fcc94542e`

| Field | Value |
|---|---|
| SHA-256 | `d292f68fcc94542edf5761239a77cd7d17f3ed5d7fc85451cefb8d2ad7bcb06b` |
| Family label | `unknown` |
| File name | `python37.dll` |
| File type | `dll` |
| First seen | `2026-10-07 04:32:01` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, dll, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08f045006ed0409784798556b77ea889` |
| SHA-1 | `76feebd05c54ec9a982c93bd165a7249c3c0e5d2` |
| SHA-256 | `d292f68fcc94542edf5761239a77cd7d17f3ed5d7fc85451cefb8d2ad7bcb06b` |
| SHA3-384 | `a65af004055191fc137cc33f203fee27232d86a7fed9444615f19706f4ed5ec8d447c0aab7863d79005df096f342b7e5` |
| IMPHASH | `7c49acab6f7e595894e993c561a052e4` |
| TLSH | `T130E54A80B587C162E4007A705980E6E7F66C2E523DB55BC7B6B837BE9DFB5C021A2F41` |
| SSDEEP | `49152:TZzPCPJZ6cRKl/2cky568hvMBISG+X1EKizRM8VwZC71fRv3fq4xhcgm7QFl7PqT:LFt3S4HsF3E8Gget0R4g0yCY` |
| ICON-DHASH | `28b4b27231b25228` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_d292f68f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d292f68fcc94542edf5761239a77cd7d17f3ed5d7fc85451cefb8d2ad7bcb06b"
    family = "unknown"
    file_name = "python37.dll"
    file_type = "dll"
    first_seen = "2026-10-07 04:32:01"
  condition:
    hash.sha256(0, filesize) == "d292f68fcc94542edf5761239a77cd7d17f3ed5d7fc85451cefb8d2ad7bcb06b"
}
```

### Sample 12: `fed1a1556b70e2d6`

| Field | Value |
|---|---|
| SHA-256 | `fed1a1556b70e2d634b05a951a4c5f89617d80e1b1cde5c620f7cf7b2970fdd5` |
| Family label | `unknown` |
| File name | `cx-programmer 9.1 free download full.exe` |
| File type | `exe` |
| First seen | `2026-10-07 04:31:41` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `954d1293832b5296971ed38e973a9203` |
| SHA-1 | `0ea03d0aeaf2bd97bf5be2a8f6e6285952881249` |
| SHA-256 | `fed1a1556b70e2d634b05a951a4c5f89617d80e1b1cde5c620f7cf7b2970fdd5` |
| SHA3-384 | `988c65339a84a893629d706b5c524c46869116caad14d1e967282e2629aee3a48b468f9248a86d42fba8f700bbff1e8e` |
| IMPHASH | `d9c51ea96e8ef1afcbca50ea21b8ac64` |
| TLSH | `T1FB25DF0FF24D4287DFF19DF05285843EBA51BB4947E137EB2BD64A3D2E5A6D1AA34200` |
| SSDEEP | `24576:bcu2/AZQJQwUD5eAcj51lirYH1yc6Y4Jm:bc/4ZQeDNe1AcoHxm` |
| ICON-DHASH | `c89496e8e8e8b2cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_fed1a155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fed1a1556b70e2d634b05a951a4c5f89617d80e1b1cde5c620f7cf7b2970fdd5"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.exe"
    file_type = "exe"
    first_seen = "2026-10-07 04:31:41"
  condition:
    hash.sha256(0, filesize) == "fed1a1556b70e2d634b05a951a4c5f89617d80e1b1cde5c620f7cf7b2970fdd5"
}
```

### Sample 13: `7bb04811138fbe63`

| Field | Value |
|---|---|
| SHA-256 | `7bb04811138fbe63e93a45e2e3afe0e68e0145e2dd06626880579922c191d611` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-10-07 04:24:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `148e6004cd5f251661970302a0bfcab2` |
| SHA-1 | `950ad8a34b9594c1e7a7cc8ee800c8e2c33ef876` |
| SHA-256 | `7bb04811138fbe63e93a45e2e3afe0e68e0145e2dd06626880579922c191d611` |
| SHA3-384 | `d27b99f6b1d9cb084d6808af0334912e0d01d6805c9c16176f73fb475c1eb93cdeab6310cf8eb4a8a369f628dca68e52` |
| TLSH | `T1ACC48C03AAF7D9B6F4A240B1115617B50963D936257BD98BDB962C90EE301C0E32D3BF` |
| TELFHASH | `t12d1259b33afe0ded37d0a801830b2b26de45a27755d431b249f355962373b828eb1839` |
| SSDEEP | `6144:wijS4vblGX+6JgglkmJlYq+cuvYyjB3GNEfMIQuaJg2:7jvxC+cbg9vYigHuag2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_7bb04811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bb04811138fbe63e93a45e2e3afe0e68e0145e2dd06626880579922c191d611"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-10-07 04:24:27"
  condition:
    hash.sha256(0, filesize) == "7bb04811138fbe63e93a45e2e3afe0e68e0145e2dd06626880579922c191d611"
}
```

### Sample 14: `91bb4e80a57b2738`

| Field | Value |
|---|---|
| SHA-256 | `91bb4e80a57b2738a6725cc20160e8f43f4398b509c104e6c4fefaec1373c703` |
| Family label | `unknown` |
| File name | `Xteam30.hta` |
| File type | `hta` |
| First seen | `2026-10-07 04:20:14` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5da0e8beab38804eadfae086f88c96ab` |
| SHA-1 | `3213da2f8545e0244807ecc8185800c0a321f370` |
| SHA-256 | `91bb4e80a57b2738a6725cc20160e8f43f4398b509c104e6c4fefaec1373c703` |
| SHA3-384 | `32479f1a4e712dbfa31053dc1aab26aacd9ac624a18199f0dfaa99fc4a0a3579d50615ccbbc6e1dae9b02d71e95e6c6e` |
| TLSH | `T19EE1C51D6E92B210EB23139E7B9F2584125CC583240EE880F14DECF87F5BB6C8753A46` |
| SSDEEP | `96:smy+6NsGwhTHQpD+da6+SlNItqqE2iW53iGEstSMgcJJhcnFEZRKnhq:sXHNsGeTHQpD+da6+SbqFtCBSHRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_91bb4e80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91bb4e80a57b2738a6725cc20160e8f43f4398b509c104e6c4fefaec1373c703"
    family = "unknown"
    file_name = "Xteam30.hta"
    file_type = "hta"
    first_seen = "2026-10-07 04:20:14"
  condition:
    hash.sha256(0, filesize) == "91bb4e80a57b2738a6725cc20160e8f43f4398b509c104e6c4fefaec1373c703"
}
```

### Sample 15: `52b29b43b3643149`

| Field | Value |
|---|---|
| SHA-256 | `52b29b43b364314968aaca8ef61f87e05d68bca81e3dfd445093c18cd6ea5ceb` |
| Family label | `NetSupport` |
| File name | `cognition.pbi` |
| File type | `zip` |
| First seen | `2026-10-07 04:14:54` |
| Reporter | `iamaachum` |
| Tags | `194-113-235-125, dropped-by-ACRStealer, NetSupport, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e9611ba6f7e50de7e59121407a49994` |
| SHA-1 | `fbea420d9eef9ccd52935dc5c213831617ec7d72` |
| SHA-256 | `52b29b43b364314968aaca8ef61f87e05d68bca81e3dfd445093c18cd6ea5ceb` |
| SHA3-384 | `3454c1136d1f8ef7a2b83afe22b4cb9afe1316f7d3d33ca87a4dbf38c6aa209e0986b04f8d15dfe23e152cf95622637a` |
| TLSH | `T1CC06334B8564925AD3B4313F7136CD86C5C2978F6E66ED4B209FD0C31B4E2AF82DA1B4` |
| SSDEEP | `98304:R5dCLqFELrn327uFG1V3p2uZ4s8SIb8Z/dDCptE7N0ySb2:R5UL3Lb0xz3BBHq8ZtC4Si` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_015_52b29b43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52b29b43b364314968aaca8ef61f87e05d68bca81e3dfd445093c18cd6ea5ceb"
    family = "NetSupport"
    file_name = "cognition.pbi"
    file_type = "zip"
    first_seen = "2026-10-07 04:14:54"
  condition:
    hash.sha256(0, filesize) == "52b29b43b364314968aaca8ef61f87e05d68bca81e3dfd445093c18cd6ea5ceb"
}
```

### Sample 16: `c57fa43fe729fc45`

| Field | Value |
|---|---|
| SHA-256 | `c57fa43fe729fc45ac725798a3f12d1eafcbe9b91c14046e98485033cb7e4fc9` |
| Family label | `NetSupport` |
| File name | `A0-6A086A5-A4djfhhryy-45.ps1` |
| File type | `ps1` |
| First seen | `2026-10-07 04:14:06` |
| Reporter | `iamaachum` |
| Tags | `194-113-235-125, dropped-by-ACRStealer, NetSupport, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2ae3848e94e1b993e92be023791103d` |
| SHA-1 | `a490617c99c1a1f999b42d989d69afebd51bd7bf` |
| SHA-256 | `c57fa43fe729fc45ac725798a3f12d1eafcbe9b91c14046e98485033cb7e4fc9` |
| SHA3-384 | `9d1a52a49f1cfe312e85ed67ff075f4093327686eb0ca011d5c6f8bac6c43e4c643c88c81c4298ba79f784588e63187a` |
| TLSH | `T1402682D97AC426F05929ABDC934774CD0794A13E6FBB280D02E1487D3D2AE1726E4CBD` |
| SSDEEP | `24576:BNE7gjh9DA9d9Rj9ChcON6nGN09ZJ9896b959ACuJscq9m9KUr9FGE9HuPIxPzaT:C` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_016_c57fa43f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c57fa43fe729fc45ac725798a3f12d1eafcbe9b91c14046e98485033cb7e4fc9"
    family = "NetSupport"
    file_name = "A0-6A086A5-A4djfhhryy-45.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 04:14:06"
  condition:
    hash.sha256(0, filesize) == "c57fa43fe729fc45ac725798a3f12d1eafcbe9b91c14046e98485033cb7e4fc9"
}
```

### Sample 17: `fef5a6cee6550248`

| Field | Value |
|---|---|
| SHA-256 | `fef5a6cee655024888d3a12b10e9cba3390e325315ef68405da9c8bf3e13a267` |
| Family label | `unknown` |
| File name | `Fabrics.a3x` |
| File type | `a3x` |
| First seen | `2026-10-07 04:13:11` |
| Reporter | `iamaachum` |
| Tags | `178-104-144-200, a3x, Arechclient2, AsgardProtector, dropped-by-ACRStealer, SectopRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5aa1c8bffdd308e5057a4eeb75563040` |
| SHA-1 | `052970815f77a6ea9ac835e6f5e37218ff716062` |
| SHA-256 | `fef5a6cee655024888d3a12b10e9cba3390e325315ef68405da9c8bf3e13a267` |
| SHA3-384 | `d7082801147d174764e58841212e2e9439e20501d2f6003b806f377ada256274b997eac2a872d1e9807ebe93b42653d8` |
| TLSH | `T18C3533A5F17DFF74843DF8E9E02F4A88448D0886C1662771A5C74E49AFB08C192F63E9` |
| SSDEEP | `24576:cVEXXs89nIZybiMLUlp5KLe+RzXewodvuNuDHQEvk+0fSJ3VA/i:cVl7KiEUJUe6ewodhDwb+fj6i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `a3x`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_fef5a6ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fef5a6cee655024888d3a12b10e9cba3390e325315ef68405da9c8bf3e13a267"
    family = "unknown"
    file_name = "Fabrics.a3x"
    file_type = "a3x"
    first_seen = "2026-10-07 04:13:11"
  condition:
    hash.sha256(0, filesize) == "fef5a6cee655024888d3a12b10e9cba3390e325315ef68405da9c8bf3e13a267"
}
```

### Sample 18: `f0712721a0095d99`

| Field | Value |
|---|---|
| SHA-256 | `f0712721a0095d99f9ce6d4650115ddb63e303d8ecefaa9916861c0b331e21a0` |
| Family label | `unknown` |
| File name | `d-56364130-1079Ef-f.ps1` |
| File type | `ps1` |
| First seen | `2026-10-07 04:11:43` |
| Reporter | `iamaachum` |
| Tags | `178-104-144-200, Arechclient2, AsgardProtector, dropped-by-ACRStealer, ps1, SectopRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc496c078f2eac7064a256585363ef4e` |
| SHA-1 | `910f67b3ce205e7b1842a0e603c14da4b3c82f62` |
| SHA-256 | `f0712721a0095d99f9ce6d4650115ddb63e303d8ecefaa9916861c0b331e21a0` |
| SHA3-384 | `2a08da830cf2c06145ad15f8373e9bf18c985bba3016a7ebc13ccc9be174e9c2bbfad71285b7fe901d4f2af1b18f0a18` |
| TLSH | `T145A3E9113BC6D6A0118F9D750CC61406BFAC9537C28D2C1C3BDDB689BF829B986ADD78` |
| SSDEEP | `3072:z9FGNCwoZ1n4n2OFoR38+jGQnietP/sbw8do7xr:5FGNCTbn4n2OFoR38+jGQnV8do7x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_f0712721
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0712721a0095d99f9ce6d4650115ddb63e303d8ecefaa9916861c0b331e21a0"
    family = "unknown"
    file_name = "d-56364130-1079Ef-f.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 04:11:43"
  condition:
    hash.sha256(0, filesize) == "f0712721a0095d99f9ce6d4650115ddb63e303d8ecefaa9916861c0b331e21a0"
}
```

### Sample 19: `ef17ba04b4f40ab8`

| Field | Value |
|---|---|
| SHA-256 | `ef17ba04b4f40ab80c46d923a4253b56236a94f2aa844b645662ae1cefefcf14` |
| Family label | `PureLogsStealer` |
| File name | `RFQ_Acquire-GT_07Oct2026.js` |
| File type | `js` |
| First seen | `2026-10-07 04:04:09` |
| Reporter | `threatcat_ch` |
| Tags | `js, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbd29a72b549f4cab5e9442d1983f29c` |
| SHA-1 | `76a4c0fa07dd8ead22c81a55f9db8c6147de267d` |
| SHA-256 | `ef17ba04b4f40ab80c46d923a4253b56236a94f2aa844b645662ae1cefefcf14` |
| SHA3-384 | `48b9adcc1922c3f592d614356549bc7951b2497be87fadccb23583efafd15f6a46d00e45a8a571905ff873bab26bbd39` |
| TLSH | `T14265228915065B5918AC07192F5F2E6461FCD8B40ACDC28BD6A9FBF3739CE81C5F2C86` |
| SSDEEP | `24576:8UhO0yGxrOR1ereLdek9+VkfPt9xwbLj9QvS8qIdkC46lHHy4ZkW:kHGhxxA+VIajDlAdDL` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_019_ef17ba04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef17ba04b4f40ab80c46d923a4253b56236a94f2aa844b645662ae1cefefcf14"
    family = "PureLogsStealer"
    file_name = "RFQ_Acquire-GT_07Oct2026.js"
    file_type = "js"
    first_seen = "2026-10-07 04:04:09"
  condition:
    hash.sha256(0, filesize) == "ef17ba04b4f40ab80c46d923a4253b56236a94f2aa844b645662ae1cefefcf14"
}
```

### Sample 20: `aa84a72e470b4a4b`

| Field | Value |
|---|---|
| SHA-256 | `aa84a72e470b4a4b8c581e5867a13118fc43756b62796556de3dfe4a688c3ddb` |
| Family label | `unknown` |
| File name | `e5d4a291-f991-47fc-85cf-dcccb773affc.ps1` |
| File type | `ps1` |
| First seen | `2026-10-07 03:54:13` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14c364b2de3ce175fcc9f32041d8d195` |
| SHA-1 | `0433b9e8b154763fdb2733ea81b773ad23fcea98` |
| SHA-256 | `aa84a72e470b4a4b8c581e5867a13118fc43756b62796556de3dfe4a688c3ddb` |
| SHA3-384 | `ce5eadef09e384776bbbee0d2c887fa9f87b81d4fb52fe206a40dcd7ec34cd423eaba2fe7e8494deafbc26fece665923` |
| TLSH | `T1D844962439C0A769224DDCB72C815C1D9AC9F477D38B6C4D39CE59C5AF879B886EC838` |
| SSDEEP | `6144:wusOGxCVWBxLcByyKffHDbHWmoG+g+G+qM1KjgeHM1F:wnMAY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_aa84a72e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa84a72e470b4a4b8c581e5867a13118fc43756b62796556de3dfe4a688c3ddb"
    family = "unknown"
    file_name = "e5d4a291-f991-47fc-85cf-dcccb773affc.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 03:54:13"
  condition:
    hash.sha256(0, filesize) == "aa84a72e470b4a4b8c581e5867a13118fc43756b62796556de3dfe4a688c3ddb"
}
```

### Sample 21: `6ee948412a06d240`

| Field | Value |
|---|---|
| SHA-256 | `6ee948412a06d2402d7967975e410a7069c75d0bcfb6afd0d7a9215579e2a5c3` |
| Family label | `unknown` |
| File name | `8d156900-bcb7-11f1-997f-ea71e2325182.ps1` |
| File type | `ps1` |
| First seen | `2026-10-07 03:53:48` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb13a6dd1fa3ceb4afc1e57cca9720dd` |
| SHA-1 | `1c42868f0c17d51d3f6c0978e290f7cafa5f8a77` |
| SHA-256 | `6ee948412a06d2402d7967975e410a7069c75d0bcfb6afd0d7a9215579e2a5c3` |
| SHA3-384 | `1abf7c3607c261104859dd65c0c64ef490828bf67c05712c091975624bac6a9823e2889883baf4b8e17840703475b814` |
| TLSH | `T12224932539C0A665254DDCB72C450C1DA9C8F477E38BA84D79CF49C5AF47AB88BEC838` |
| SSDEEP | `3072:XO0O6j5VeNx42G7xEotKLI8K/bc9yRBjgT6WbIVr2wKof:+0Oc5VeNx42PI8KpjgmjZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_6ee94841
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee948412a06d2402d7967975e410a7069c75d0bcfb6afd0d7a9215579e2a5c3"
    family = "unknown"
    file_name = "8d156900-bcb7-11f1-997f-ea71e2325182.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 03:53:48"
  condition:
    hash.sha256(0, filesize) == "6ee948412a06d2402d7967975e410a7069c75d0bcfb6afd0d7a9215579e2a5c3"
}
```

### Sample 22: `c184c0f22af4708f`

| Field | Value |
|---|---|
| SHA-256 | `c184c0f22af4708fc50708003da89f2811530f98690ab37036951c2f998d55c6` |
| Family label | `unknown` |
| File name | `Summary_Raw_v8.3.ps1` |
| File type | `ps1` |
| First seen | `2026-10-07 03:28:06` |
| Reporter | `iamaachum` |
| Tags | `CountLoader, pos-terminal-vg, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `396f02bae25dfad6f369d5d24f6e291b` |
| SHA-1 | `4b6bfed2d3ff4e21d6688380d9acb9d3a46cfc85` |
| SHA-256 | `c184c0f22af4708fc50708003da89f2811530f98690ab37036951c2f998d55c6` |
| SHA3-384 | `129615813d8bf17c29ee7c00982ee21ff2923d9a992a5ef3b806817869bc7a5f0e9094a6ec851240b52b0fef5d4fe2a0` |
| TLSH | `T1A22431823345F6BCF2CE0BA2AC070525A2F8D815F99F5188BBF17DC7679EA441574E82` |
| SSDEEP | `6144:q4PERnNE4dMLpH0b8Hgqv5YAp+Tslds7sA8fzyhKdooiZL5w009e/O5F:affVIdK/PDk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_c184c0f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c184c0f22af4708fc50708003da89f2811530f98690ab37036951c2f998d55c6"
    family = "unknown"
    file_name = "Summary_Raw_v8.3.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 03:28:06"
  condition:
    hash.sha256(0, filesize) == "c184c0f22af4708fc50708003da89f2811530f98690ab37036951c2f998d55c6"
}
```

### Sample 23: `135607f1e8aafbb7`

| Field | Value |
|---|---|
| SHA-256 | `135607f1e8aafbb7b49de471400f3d30399101096583f418bcbd18cca8e700be` |
| Family label | `unknown` |
| File name | `ZateEngine.exe` |
| File type | `exe` |
| First seen | `2026-10-07 03:26:00` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-YapStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6a15f268d9096d80dc647fbb6219fc4` |
| SHA-1 | `bc3304292c6379a2c1c7630edaed5c4f3ce5d1b0` |
| SHA-256 | `135607f1e8aafbb7b49de471400f3d30399101096583f418bcbd18cca8e700be` |
| SHA3-384 | `8575dfd64cd713d39f710c130485bfc991c46d531f60f0d0058e36bdbd722a6654e20275cabc6453171126dee0ce4d16` |
| IMPHASH | `855ce6118e717552c81749ca2f14b7ad` |
| TLSH | `T10806BF4AAAE60124E2F7A63556EB4112D63BBD010B34CEDF3A8C55690F73BC46172F39` |
| SSDEEP | `49152:43jjoURTW62cpF0c99lH/q+HW7UWdx1MZo728XRjYjz+eb47ZcCHynM9b2KWFpIP:43JZxRSh5AZllMnnCKSX/` |
| ICON-DHASH | `8671cc9c94cc6132` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_135607f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135607f1e8aafbb7b49de471400f3d30399101096583f418bcbd18cca8e700be"
    family = "unknown"
    file_name = "ZateEngine.exe"
    file_type = "exe"
    first_seen = "2026-10-07 03:26:00"
  condition:
    hash.sha256(0, filesize) == "135607f1e8aafbb7b49de471400f3d30399101096583f418bcbd18cca8e700be"
}
```

### Sample 24: `2e65411b686c1554`

| Field | Value |
|---|---|
| SHA-256 | `2e65411b686c155415d7644f88ba91cb67c715e5b1a7094962732749358142cc` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-10-07 03:09:13` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, content-duskrunner-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bf544ef058d82ba7738323ac77b367e` |
| SHA-1 | `76829e5eb90b257392e66fd2de0c81b61fe18a1c` |
| SHA-256 | `2e65411b686c155415d7644f88ba91cb67c715e5b1a7094962732749358142cc` |
| SHA3-384 | `85fcaac5ce71ca2de1d4660d5d706a5ebbdfdf60a001b295a7f796eb0c0face60ec73a3d295c538a5594a4a7d319ab98` |
| TLSH | `T12787332504935F96C97D513E81EB4F427A58AB9EC056E30D07A2D26D3FF33F0AD22686` |
| SSDEEP | `786432:pvZzIZXDSJD1/VrG8J8DsXEDa3SZdgib7A3cS6lg1ETfzJqAs51vEy1e:pdgTSv5G8IsXEDa3SPgb3cSf1JHE0e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_2e65411b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e65411b686c155415d7644f88ba91cb67c715e5b1a7094962732749358142cc"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-10-07 03:09:13"
  condition:
    hash.sha256(0, filesize) == "2e65411b686c155415d7644f88ba91cb67c715e5b1a7094962732749358142cc"
}
```

### Sample 25: `8c65239167f3ec60`

| Field | Value |
|---|---|
| SHA-256 | `8c65239167f3ec609a5a992ed143b68b3c1b3a5985cf8a6d3f528081de15d0ee` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-10-07 03:07:58` |
| Reporter | `iamaachum` |
| Tags | `exe, ilia-from-izhevsk-club, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e29dd50712b2f02b0464b835e6f30af` |
| SHA-1 | `4a997e8b82985ca758503c6ac6825c77b9fd394b` |
| SHA-256 | `8c65239167f3ec609a5a992ed143b68b3c1b3a5985cf8a6d3f528081de15d0ee` |
| SHA3-384 | `9b05e549fc2d3e1de4ea5c0b515bd7119400d9a6cc1c7afb83a66692562f71b54beb348a5e0062803913bfccf1e896f5` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T1A51633171202BCF1F2FA633251A825457CE4AE675275EFB9C508435FB9A33E81A6C723` |
| SSDEEP | `98304:a+h77Dw34jm8qq2VsIWvhL1fdf8nWSD5CzbNzhLnfdVvgj:a4T3j48h5fgW0KVhYj` |
| ICON-DHASH | `08343272b1125a28` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_8c652391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c65239167f3ec609a5a992ed143b68b3c1b3a5985cf8a6d3f528081de15d0ee"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 03:07:58"
  condition:
    hash.sha256(0, filesize) == "8c65239167f3ec609a5a992ed143b68b3c1b3a5985cf8a6d3f528081de15d0ee"
}
```

### Sample 26: `d0fae14af3bda82a`

| Field | Value |
|---|---|
| SHA-256 | `d0fae14af3bda82a509889852346f4797e6232e03a29f2f7142e574f6aca127e` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-10-07 03:05:20` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, file-pumped, patch-cobaltwave-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4975538c030469b6170ec110d1dec542` |
| SHA-1 | `2bfd2d25f44050b8a089f1a83e676df96cd92f6a` |
| SHA-256 | `d0fae14af3bda82a509889852346f4797e6232e03a29f2f7142e574f6aca127e` |
| SHA3-384 | `39203637bfad8b487532817eefe1998a2574239924bd9ba23776fe5a7afabd1a3d76e958a2f2818d2fda793d54462c34` |
| TLSH | `T1B1F62325F4453671F88EC6B405B02DA403E4AD76236F0BC82239B45F9663E7D9F78A36` |
| SSDEEP | `393216:cxDm6jkMy/7cLV6u0iw7oOSK6WQCXY0iw7oOSK6WQSyRpIy7+Ayo3SySFk8Ra:KDYDmwu05oOSUQb05oOSUQS8H7+Ayo3f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_d0fae14a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0fae14af3bda82a509889852346f4797e6232e03a29f2f7142e574f6aca127e"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-10-07 03:05:20"
  condition:
    hash.sha256(0, filesize) == "d0fae14af3bda82a509889852346f4797e6232e03a29f2f7142e574f6aca127e"
}
```

### Sample 27: `dc978cecad6e55b1`

| Field | Value |
|---|---|
| SHA-256 | `dc978cecad6e55b168f42ffcaab296a4513c3a46af58707fb1f6af5d162a69e0` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-10-07 03:01:40` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, exe, ValetiStealer, veliomelio-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa553cae460341d33e5b04d4296c601e` |
| SHA-1 | `10b0b5bbc48e6b9bfc70eba5e3d099b68e96c802` |
| SHA-256 | `dc978cecad6e55b168f42ffcaab296a4513c3a46af58707fb1f6af5d162a69e0` |
| SHA3-384 | `8c0253bd72244db52ffa380a446b5ee0a9e7b9a613f17a6860395ae13852cca8d2d4aba6ef843d988e21a483541f1d16` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1DDC6238213D018A1E0F9D7744EF283979231BCEB4A2DD79F27D8B4952E625C19E3631B` |
| SSDEEP | `49152:CBmVjeQqjb/7wNzuf8vor2rK0u26CTzt38AXPEQ84SwR9Su:BVjeLjwg8X16STPEQ8414u` |
| ICON-DHASH | `24e4cacccec8f8b1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_dc978cec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc978cecad6e55b168f42ffcaab296a4513c3a46af58707fb1f6af5d162a69e0"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 03:01:40"
  condition:
    hash.sha256(0, filesize) == "dc978cecad6e55b168f42ffcaab296a4513c3a46af58707fb1f6af5d162a69e0"
}
```

### Sample 28: `749009376b352dfd`

| Field | Value |
|---|---|
| SHA-256 | `749009376b352dfd21f7289f549c0ed3ff515f813eb1eaf2e604ba75be02c9c2` |
| Family label | `unknown` |
| File name | `Installer21691x64.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:59:57` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `770e477b5f8cd94a6783140a3bb62225` |
| SHA-1 | `36c20408877494fe44a04809a7730efc0d0a323a` |
| SHA-256 | `749009376b352dfd21f7289f549c0ed3ff515f813eb1eaf2e604ba75be02c9c2` |
| SHA3-384 | `df30ca2580e525a4ae6fcaa02c10e8c6bb9acfbb6f7859d1c3ded2de0752da3059300bed0982fc4bc01a22d633f2c53a` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T1CD07337D31C8042CE68CEF3B173BB58882EBBD366D389125E245F1BD5534AE152F1A29` |
| SSDEEP | `393216:cpxQTv84vaMxyerYiSX6Rse9SWC6Yuh7Ueh:gRlesiNRseIpAV9h` |
| ICON-DHASH | `686c74f4c298e4e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_74900937
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749009376b352dfd21f7289f549c0ed3ff515f813eb1eaf2e604ba75be02c9c2"
    family = "unknown"
    file_name = "Installer21691x64.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:59:57"
  condition:
    hash.sha256(0, filesize) == "749009376b352dfd21f7289f549c0ed3ff515f813eb1eaf2e604ba75be02c9c2"
}
```

### Sample 29: `29ab58d7ef08f98b`

| Field | Value |
|---|---|
| SHA-256 | `29ab58d7ef08f98ba4cb0e20b0989eb8460c6247283c530d41bc9dcf67a9e711` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-10-07 02:59:26` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5de2a03c256cbe4b89e8b4ea0da8df7` |
| SHA-1 | `aa64e137c6d4de7efec5deeec45f78efcd79e92f` |
| SHA-256 | `29ab58d7ef08f98ba4cb0e20b0989eb8460c6247283c530d41bc9dcf67a9e711` |
| SHA3-384 | `9647e70003c95b66758f925295c9e90e41aeca9e1081cd114303e2c47e85f41bf8ef6eb43d91cf12866eca2dd29466fb` |
| TLSH | `T1BB07337D3588042CE68CEE3B173BB58882EBBD362D389115F249F1BD5634AD152F1B29` |
| SSDEEP | `393216:GpxQTv84vaMxyerYiSX6Rse9SWC6Yuh7Ueh:mRlesiNRseIpAV9h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_29ab58d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ab58d7ef08f98ba4cb0e20b0989eb8460c6247283c530d41bc9dcf67a9e711"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-07 02:59:26"
  condition:
    hash.sha256(0, filesize) == "29ab58d7ef08f98ba4cb0e20b0989eb8460c6247283c530d41bc9dcf67a9e711"
}
```

### Sample 30: `2c195b625dee9271`

| Field | Value |
|---|---|
| SHA-256 | `2c195b625dee9271f543a9be087c9fb1b641255be29cc7c88fd811f7e1fe71d5` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:58:49` |
| Reporter | `iamaachum` |
| Tags | `exe, up4pc-com, vlad-nazarenko2004-club, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5af41a745941cdc66963b2007167547f` |
| SHA-1 | `cb7e46f215d6bd8f121ebb4685c7e282a2090b9c` |
| SHA-256 | `2c195b625dee9271f543a9be087c9fb1b641255be29cc7c88fd811f7e1fe71d5` |
| SHA3-384 | `383f836adf6a22fb952a9947ac3a42261eb7721438c1cc09389c9970a9863fee01731f2bfde44ac3b0bee1032ceef080` |
| IMPHASH | `736bcf4c461b6db22919613fa59ecda8` |
| TLSH | `T1A725084B7B416E71D4DC2C7AAA900D82DB75B909EBECB737161ABFDA04661C040F12E7` |
| SSDEEP | `12288:EZus2fZEpb1y8dN+zTfyAY4zrbj+2+3Ao5N1H/bYU5oFm:E28BdNKPzXj+2+Qo5N1Hzmm` |
| ICON-DHASH | `6eb37969b1696a36` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_2c195b62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c195b625dee9271f543a9be087c9fb1b641255be29cc7c88fd811f7e1fe71d5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:58:49"
  condition:
    hash.sha256(0, filesize) == "2c195b625dee9271f543a9be087c9fb1b641255be29cc7c88fd811f7e1fe71d5"
}
```

### Sample 31: `2dbc1c3920315f24`

| Field | Value |
|---|---|
| SHA-256 | `2dbc1c3920315f24899eb0f9574d0c5e2e0c5b42d280b6a7a506b176305f7b09` |
| Family label | `unknown` |
| File name | `Setup_latest.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:56:43` |
| Reporter | `iamaachum` |
| Tags | `bobilittelpony-com, exe, SpaxMedia, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76c73259f756d7367280719ecc4ac8fd` |
| SHA-1 | `586cdd83d9f149e59e9d10547cd228ee35870503` |
| SHA-256 | `2dbc1c3920315f24899eb0f9574d0c5e2e0c5b42d280b6a7a506b176305f7b09` |
| SHA3-384 | `4eea6c125a13b3eb08a064d17220d70b9d670c2ca03522d339776533eac692d65125d709baffebc111d8a1474a7b74b1` |
| IMPHASH | `e8651af884755a99888495c115c825d9` |
| TLSH | `T1E7873392F78FDAAAEFA78476DA9D0570E7317C6AC265F67D0228CD180C5648C05273F2` |
| SSDEEP | `786432:b3WtVa0z/EQXw24OYm23t0GXqAvyuIILkcPgFuk2aAEjomOfuWt:zya0z/EQ6Ot0t0GzPL5PF2LomOfuWt` |
| ICON-DHASH | `20168e484c4c0800` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_2dbc1c39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dbc1c3920315f24899eb0f9574d0c5e2e0c5b42d280b6a7a506b176305f7b09"
    family = "unknown"
    file_name = "Setup_latest.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:56:43"
  condition:
    hash.sha256(0, filesize) == "2dbc1c3920315f24899eb0f9574d0c5e2e0c5b42d280b6a7a506b176305f7b09"
}
```

### Sample 32: `27c743d1ff6531bc`

| Field | Value |
|---|---|
| SHA-256 | `27c743d1ff6531bcd8fb09f0a91caea95ad72c34e83782660236b6b34b81cde5` |
| Family label | `unknown` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:55:34` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, wooocommerce-shopping` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b35c97702037bcd235041c6bc786da1` |
| SHA-1 | `36e039dd00e7ad1a8b1cd256af3e66a137e983df` |
| SHA-256 | `27c743d1ff6531bcd8fb09f0a91caea95ad72c34e83782660236b6b34b81cde5` |
| SHA3-384 | `982f05370bcba3392250c3073dc401282e096f91406ff1e00540eee3efc30a32677a1a72d5d0a168cf3392508df7387f` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T11ED61813665800ECC49BD770C5B39A6766B57C8E873537AB8E60BEB42F527806F79B00` |
| SSDEEP | `49152:g2n2q7lik2NPrAuptPjf6KdWJv6P6vFBIQOQsqLZcKC0DZyERsyhrC3b:vRw/5ERFhi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_27c743d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27c743d1ff6531bcd8fb09f0a91caea95ad72c34e83782660236b6b34b81cde5"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:55:34"
  condition:
    hash.sha256(0, filesize) == "27c743d1ff6531bcd8fb09f0a91caea95ad72c34e83782660236b6b34b81cde5"
}
```

### Sample 33: `dba820c1f2c47781`

| Field | Value |
|---|---|
| SHA-256 | `dba820c1f2c4778166063b0a20563b51c160ee6a3b08e4d5c2d4d7153a3ec081` |
| Family label | `unknown` |
| File name | `cx-programmer 9.1 free download full_patched.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:54:33` |
| Reporter | `iamaachum` |
| Tags | `de-pumped, exe, rogaldorn3-website, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f54b4f48c6661e798e28c2213fc1007e` |
| SHA-1 | `aece710317306131858f0b1be93b96cd1cfef94e` |
| SHA-256 | `dba820c1f2c4778166063b0a20563b51c160ee6a3b08e4d5c2d4d7153a3ec081` |
| SHA3-384 | `6c67736a30fdcd1eaa7a5f506b87b61ec01da055ff53924ba5772e7e6700e730dfb45b56c692fb2c064a9c408c743ea7` |
| IMPHASH | `d9c51ea96e8ef1afcbca50ea21b8ac64` |
| TLSH | `T14F679D03F7D84075E2FB2630252AA636767EBD201FE081CB679566AE2D717C19E3035B` |
| SSDEEP | `393216:VD7WotCh4G5yMOLIXHod/P2JjLO+IeEv9jYLRWax4akUdaHoBNONnn:VPNxIjOLCodn2Jjy+Ibar4akUAYNOx` |
| ICON-DHASH | `c89496e8e8e8b2cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_dba820c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba820c1f2c4778166063b0a20563b51c160ee6a3b08e4d5c2d4d7153a3ec081"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full_patched.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:54:33"
  condition:
    hash.sha256(0, filesize) == "dba820c1f2c4778166063b0a20563b51c160ee6a3b08e4d5c2d4d7153a3ec081"
}
```

### Sample 34: `01a6d7a943d1287a`

| Field | Value |
|---|---|
| SHA-256 | `01a6d7a943d1287a48936923b86b46b6a5e094ac5cb8803510a2f408d36e6239` |
| Family label | `unknown` |
| File name | `dissmpsl` |
| File type | `elf` |
| First seen | `2026-10-07 02:54:25` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38a411048053fe833043f06589b5b40a` |
| SHA-1 | `3d74e2bf94a89a1e5cffade7d0182300ec6a35f6` |
| SHA-256 | `01a6d7a943d1287a48936923b86b46b6a5e094ac5cb8803510a2f408d36e6239` |
| SHA3-384 | `6f5c6d01030e9cd475ca2d0288a36a0de89e991077ad6b4e8cd0d97ffa47193f28b2d7fbb484c6844209b0d2ba75fc16` |
| TLSH | `T1C574B51ABB519EBBC85FCE3302EA4A1110CDE44612996B6BB7B4C61CF74BD0E48E3D54` |
| TELFHASH | `t1c6612205a43d09d9de231c196c686ff35957e52a32e6bb28ff1addc0084e429f158e0f` |
| SSDEEP | `6144:pmhbP5ynZR37lWzsaE8jv3HtjG45Fh5t+COAYP:pyqHlWzsa/v3HtjG45Fh5t+COAYP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_01a6d7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01a6d7a943d1287a48936923b86b46b6a5e094ac5cb8803510a2f408d36e6239"
    family = "unknown"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-07 02:54:25"
  condition:
    hash.sha256(0, filesize) == "01a6d7a943d1287a48936923b86b46b6a5e094ac5cb8803510a2f408d36e6239"
}
```

### Sample 35: `a0df6a94057dfad6`

| Field | Value |
|---|---|
| SHA-256 | `a0df6a94057dfad6ec1b8985845d9517ff7c5ac7257fa7eedc0b8a058f7154e4` |
| Family label | `unknown` |
| File name | `cx-programmer 9.1 free download full.7z` |
| File type | `7z` |
| First seen | `2026-10-07 02:53:39` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-1673, rogaldorn3-website, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b15d80e78194eda4ab583ee9964db193` |
| SHA-1 | `fcfd6ce62ab608021d1b0265740e185bdedcfeb2` |
| SHA-256 | `a0df6a94057dfad6ec1b8985845d9517ff7c5ac7257fa7eedc0b8a058f7154e4` |
| SHA3-384 | `e9a13e74bba5c68a8c085a9c17253e1f55f12bf8d645d6d4acae2c2fc50db8237f36a134d764d8e57f5052612723cfeb` |
| TLSH | `T1CDE6330EE86DE25808BF9FE6E0632D47AF528372E3393291359111271DBFBD9B145217` |
| SSDEEP | `393216:GpzfBjXq+VVTrf7CgmXOG9hHvdXPRVqrA47mqmD0e1wisP:Wbz7Czb9hHvZPR8A47o08u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_a0df6a94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0df6a94057dfad6ec1b8985845d9517ff7c5ac7257fa7eedc0b8a058f7154e4"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-10-07 02:53:39"
  condition:
    hash.sha256(0, filesize) == "a0df6a94057dfad6ec1b8985845d9517ff7c5ac7257fa7eedc0b8a058f7154e4"
}
```

### Sample 36: `b17689e3da2c11a8`

| Field | Value |
|---|---|
| SHA-256 | `b17689e3da2c11a8034dee9389c5577366a3b4cbdfc77419c997713d5082dfc5` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:52:41` |
| Reporter | `iamaachum` |
| Tags | `exe, shlyapunabuche-com, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcf3b88561b92b4edb0682c8b799b37b` |
| SHA-1 | `cf040f5b58723f8836905b8d932994e26ed2ad47` |
| SHA-256 | `b17689e3da2c11a8034dee9389c5577366a3b4cbdfc77419c997713d5082dfc5` |
| SHA3-384 | `b4cb2877b36dfcb0b8a341f01ab21d01fb58319680c14711829d61f775a53227e1f6bb81f89b0e2524587aaa49040574` |
| IMPHASH | `1f2032c00f477c916b488c1ab1e74af1` |
| TLSH | `T1ED25CE06E95242AED52240F9C3B121C29E72BF441B64C5FB96D5092D4EF6DF01EFB2AC` |
| SSDEEP | `12288:JTOPv++9+I4iKsxxT/SQUR9SLrdx3BXOFtdmQg2BAG6fmY78JlDkFo7RGM/r5:9OP2Ar/Szk3BXI7mOBufmZfDzfr5` |
| ICON-DHASH | `08542aaaaa9a6410` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_b17689e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b17689e3da2c11a8034dee9389c5577366a3b4cbdfc77419c997713d5082dfc5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:52:41"
  condition:
    hash.sha256(0, filesize) == "b17689e3da2c11a8034dee9389c5577366a3b4cbdfc77419c997713d5082dfc5"
}
```

### Sample 37: `d16d828d6538f903`

| Field | Value |
|---|---|
| SHA-256 | `d16d828d6538f903ab4b487994ced8f19a7cffc23944d30b7b724a194628b443` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-10-07 02:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3517a69209242e49f8e1f463732f656` |
| SHA-1 | `fd98b7429f0fa125902ef8cb2252ee9854991593` |
| SHA-256 | `d16d828d6538f903ab4b487994ced8f19a7cffc23944d30b7b724a194628b443` |
| SHA3-384 | `ae713daa8ffb03431c54d24d840ff8552bf1ffc2d7a9af928d8543ba0c940c8b880c1b11a17f7f5249b9203e0bd3ef12` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T165946BADAE7CADEFD66FC075D5948E9597416032135BA3438007A0EA9C0CEA2DD309F7` |
| SSDEEP | `6144:xCB1QrTwSSkHv7B0+N1KfoUk7ZmRP/5IxcnrfRb5+/n0oFfO/GPuUqnXv:x+Qoy0+jzmWcrY0yfO/GPuUqnXv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_d16d828d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d16d828d6538f903ab4b487994ced8f19a7cffc23944d30b7b724a194628b443"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-10-07 02:52:09"
  condition:
    hash.sha256(0, filesize) == "d16d828d6538f903ab4b487994ced8f19a7cffc23944d30b7b724a194628b443"
}
```

### Sample 38: `372f8a434264575c`

| Field | Value |
|---|---|
| SHA-256 | `372f8a434264575c7adeaf66ffc090b454fab89a1ac5f49986f2a9ed8d25d357` |
| Family label | `unknown` |
| File name | `𝗦𝗘𝗧𝗨𝗣.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:51:56` |
| Reporter | `iamaachum` |
| Tags | `exe, hlomidiyaco-com, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54fe1c9789a24b53141411cc1aeae09c` |
| SHA-1 | `fef8480dfb33cc24d8299905c9a9db00ae78e58c` |
| SHA-256 | `372f8a434264575c7adeaf66ffc090b454fab89a1ac5f49986f2a9ed8d25d357` |
| SHA3-384 | `e7b1a204fd1d762cacb7b94a084441f3068784a2cfe0f2fa5e1981e371eaa30e161864436b8b377d236b160821373140` |
| IMPHASH | `a269e8f623954737e7ed5ff61ebfb93f` |
| TLSH | `T1A125DF85F3A90FF6F8254CF44A945346BA7C788DEBF866BF425E05365E022E506FC260` |
| SSDEEP | `12288:GKt+P9BWf/4pYItzQntTv7T8SX6+fhdTCFq2co8eLe152+pqLXzNghxO:1tI9BUIzALXdyFvcreLeusqTzNghxO` |
| ICON-DHASH | `2909696969692004` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_372f8a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372f8a434264575c7adeaf66ffc090b454fab89a1ac5f49986f2a9ed8d25d357"
    family = "unknown"
    file_name = "𝗦𝗘𝗧𝗨𝗣.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:51:56"
  condition:
    hash.sha256(0, filesize) == "372f8a434264575c7adeaf66ffc090b454fab89a1ac5f49986f2a9ed8d25d357"
}
```

### Sample 39: `b85d4673ac19ee20`

| Field | Value |
|---|---|
| SHA-256 | `b85d4673ac19ee208e96eff1e860d4b110a1eac0620464193bde12a85fb54115` |
| Family label | `Formbook` |
| File name | `PO.2610041 Dan PO.2610042.pdf.js` |
| File type | `js` |
| First seen | `2026-10-07 02:49:34` |
| Reporter | `threatcat_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87ea9c3b2ac9ee65f0f3758ff830d1c3` |
| SHA-1 | `14a64ef484b738b7bb430fec1ccbd792b57b6f0a` |
| SHA-256 | `b85d4673ac19ee208e96eff1e860d4b110a1eac0620464193bde12a85fb54115` |
| SHA3-384 | `147c18ed29c34c69e74143d0a6c193fd957460cb2311d34444f80ebb415b53cf4c2bd88087db728c2668db2d99049f7f` |
| TLSH | `T115A2BB44158638846373ABBAE71AA8D4F37B06770098490BB8BC6055EFF1D1CDEE4DB5` |
| SSDEEP | `384:XnK+NmytyAncnzeL8vHs/5pvlcmVZRvpSt1GFeehbGf3ZMBle1Dg:XXNmUtncnzewvHs/5pvlcmVZBpSt1GMM` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_039_b85d4673
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b85d4673ac19ee208e96eff1e860d4b110a1eac0620464193bde12a85fb54115"
    family = "Formbook"
    file_name = "PO.2610041 Dan PO.2610042.pdf.js"
    file_type = "js"
    first_seen = "2026-10-07 02:49:34"
  condition:
    hash.sha256(0, filesize) == "b85d4673ac19ee208e96eff1e860d4b110a1eac0620464193bde12a85fb54115"
}
```

### Sample 40: `eff4b583d6a3e074`

| Field | Value |
|---|---|
| SHA-256 | `eff4b583d6a3e0743b7ad853a8227cc04b83eb4d855cac31bdef4fb0185326a9` |
| Family label | `unknown` |
| File name | `𝐒𝐄𝐓𝐔𝐏.exe` |
| File type | `exe` |
| First seen | `2026-10-07 02:48:16` |
| Reporter | `iamaachum` |
| Tags | `exe, rogaldorn2-website, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9a8bc2237b95e0543c5dc67192de2b5` |
| SHA-1 | `6fbd4c488024b13f36ddcd0eeb73403fca6758bf` |
| SHA-256 | `eff4b583d6a3e0743b7ad853a8227cc04b83eb4d855cac31bdef4fb0185326a9` |
| SHA3-384 | `af7389ea3769a57a89a6483b0881faac625cbb3829a6acc1d2f2fa32f7970f02de8672314cfa9032fc6cc1b66f52071f` |
| IMPHASH | `245b9cd9dcd776cb6161e6ec4e0585fb` |
| TLSH | `T1BB2538E53F851EFAF7505935C2AA036A82EBF906D2D488E6E65D88775A00CC07DF1C2D` |
| SSDEEP | `24576:N2YM6PB435Qt862CCTxbAQE209ZUSYyCoGihMKO:McZ4JQCFCQE20QVKM` |
| ICON-DHASH | `1032317969690000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_eff4b583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff4b583d6a3e0743b7ad853a8227cc04b83eb4d855cac31bdef4fb0185326a9"
    family = "unknown"
    file_name = "𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:48:16"
  condition:
    hash.sha256(0, filesize) == "eff4b583d6a3e0743b7ad853a8227cc04b83eb4d855cac31bdef4fb0185326a9"
}
```

### Sample 41: `187089dffb448a9f`

| Field | Value |
|---|---|
| SHA-256 | `187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a` |
| Family label | `unknown` |
| File name | `187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a.exe` |
| File type | `exe` |
| First seen | `2026-10-07 01:58:57` |
| Reporter | `Kejult` |
| Tags | `exe, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00e964422ebcfb8dce11fbe450fa09ce` |
| SHA-1 | `5c0a4a06faf3adff3fad5722cb124751daee20a6` |
| SHA-256 | `187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a` |
| SHA3-384 | `4320455392728a3a5632c50f24e493015ef4d355202cd51720d4d7a1f7c3b9ffed1e3dd660a5f3063be768069994329d` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T10E381207328800ECC98BD77544B55A7A12F23DEE5132BB4A0FA57EA02F177966F68F44` |
| SSDEEP | `3145728:nTcz3G/QmMUPwMGdYNW1zcR4z3WIoVJPILBAc:QLwMUPwMDNgze+3WIoTPI/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_187089df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a"
    family = "unknown"
    file_name = "187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:58:57"
  condition:
    hash.sha256(0, filesize) == "187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a"
}
```

### Sample 42: `a36fbc117b0582e0`

| Field | Value |
|---|---|
| SHA-256 | `a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a` |
| Family label | `unknown` |
| File name | `a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a.exe` |
| File type | `exe` |
| First seen | `2026-10-07 01:57:29` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c756d5f25076629543879497dbd7e70a` |
| SHA-1 | `7742ba42e3f368dcf816f36783e446ab72e0b04e` |
| SHA-256 | `a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a` |
| SHA3-384 | `2ea251d4ec90072acb7dfb6a08338e10a5aba48eb7817cdaffb4cabc1292406f0363e9d8ca86a4903ef5dedeceda8707` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T10CF60807638810DCDA4BD77184B45E7922F23CEE91327B5A0F95BEA02F167956F6CB08` |
| SSDEEP | `49152:Oj/G6TGYfCe5qCJXYM9+YbkTo4GC0q3hI4Az8GtOgFy0YF66oCvWVLIUGTdosJjq:O5BrgPv60caK82` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_a36fbc11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a"
    family = "unknown"
    file_name = "a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:57:29"
  condition:
    hash.sha256(0, filesize) == "a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a"
}
```

### Sample 43: `7ffa8ceaba695ecb`

| Field | Value |
|---|---|
| SHA-256 | `7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9` |
| Family label | `unknown` |
| File name | `7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9.exe` |
| File type | `exe` |
| First seen | `2026-10-07 01:57:09` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1daec83a0a8e7909926a47f945058b89` |
| SHA-1 | `45f3ab20cc78e6da974703f7bf65dee8493b39df` |
| SHA-256 | `7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9` |
| SHA3-384 | `21dc2006e5da286e9bda78e16d115826118bad4bae7420da42171b9809ef141bc5fc5abaaddb1bc3d0b82655cb78b562` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1A8C6E757338810ECCA8BDA7144B0597922B13DAE50327B6E0EE5BE902F1B7556F6CF09` |
| SSDEEP | `49152:CVOMyojiJnqvmNdUXJb4Mdhs2loH1+y6YjyztOMnoC6KW+BQs6/WTqj:zoObVYtN7PFTqj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_7ffa8cea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9"
    family = "unknown"
    file_name = "7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:57:09"
  condition:
    hash.sha256(0, filesize) == "7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9"
}
```

### Sample 44: `8b3b5fcac17c2be4`

| Field | Value |
|---|---|
| SHA-256 | `8b3b5fcac17c2be4accd5c596d8b51184f39e6cf65ebcac939d02041cedf502e` |
| Family label | `Mirai` |
| File name | `dissarm7` |
| File type | `elf` |
| First seen | `2026-10-07 01:56:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2a83c03ac4a6c3ecf57f86cf0851ba7` |
| SHA-1 | `ad611e5e12ac4fcb8db8cf73607b15b537ecc083` |
| SHA-256 | `8b3b5fcac17c2be4accd5c596d8b51184f39e6cf65ebcac939d02041cedf502e` |
| SHA3-384 | `cca0f9fb4815d28b515ab72e44f83f764261b31cac7e4a45e31b161f7d71c13e4bd0a15854ca39086d85e656a881bc31` |
| TLSH | `T1D6542B08FE404F5BC1E237B9FB9F028A33339B58A7E7B20699245BB437C6B595E21115` |
| TELFHASH | `t167311f06a13d85aa5ea12c1ccd2c6bb2041b8b237252be35ff09dcc4682e402f968d4b` |
| SSDEEP | `6144:Bqxr1tJ0DPxH2eYMfDJRUarb1GQ1NjoayZRZPQm2aDkyV/GAwma2Egb72S:BqxEWPSDJRUarbz1NjNsZPQm7/imaNgZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_8b3b5fca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b3b5fcac17c2be4accd5c596d8b51184f39e6cf65ebcac939d02041cedf502e"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-07 01:56:23"
  condition:
    hash.sha256(0, filesize) == "8b3b5fcac17c2be4accd5c596d8b51184f39e6cf65ebcac939d02041cedf502e"
}
```

### Sample 45: `77a8d1bcbc9c79e7`

| Field | Value |
|---|---|
| SHA-256 | `77a8d1bcbc9c79e76e64b5fd50aeda23d4d9a0ca42299f0f7a72f8da032fcc54` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-10-07 01:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3860c03927290688db2f7769140103e4` |
| SHA-1 | `7749c4f833ed400b43cb2188de2e45420a06d441` |
| SHA-256 | `77a8d1bcbc9c79e76e64b5fd50aeda23d4d9a0ca42299f0f7a72f8da032fcc54` |
| SHA3-384 | `c7ddd1781cf6b4af5321ff2b85b9ef0b1deb8debfdaf1beb259babafb9327889ae518390c909bef639d87807040d8901` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19D947D9DAE7CADEFD6AFC0B9C4948E9597416036131AA7438103E0EA9D0CE92DD305F7` |
| SSDEEP | `6144:H+F9Xh6cTwSSkHv7B0+N1KfoUk7ZmRP0iol6BbCecNZbYQuTQnfaKYt6/Hwz6:ecXy0+jzmsOBGecN0QnfaKYt6/Hwz6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_77a8d1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a8d1bcbc9c79e76e64b5fd50aeda23d4d9a0ca42299f0f7a72f8da032fcc54"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-10-07 01:52:13"
  condition:
    hash.sha256(0, filesize) == "77a8d1bcbc9c79e76e64b5fd50aeda23d4d9a0ca42299f0f7a72f8da032fcc54"
}
```

### Sample 46: `b106a8b8ffa1c67e`

| Field | Value |
|---|---|
| SHA-256 | `b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76` |
| Family label | `unknown` |
| File name | `b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76.exe` |
| File type | `exe` |
| First seen | `2026-10-07 01:50:28` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2d8a7fa418143a4542b28c53e86a080` |
| SHA-1 | `d60a47075c410509c0bc77eab2ea58dc759487e6` |
| SHA-256 | `b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76` |
| SHA3-384 | `03de5fed56947f99729c102dad03e5bb511fd1dde4dce1bda7cfe95818893b85925d9ddd33fb836fa244191122b63710` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1CDC60947728800ECC98BD77544B15E7A12F23DEE5122BB4A0F997EA02F177956F68F08` |
| SSDEEP | `49152:S01Zdh9X2Qlb2jVPz8Jw7lzDY8ClWug9WDTYJcfgAwZvRJbbz:TPCYtG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_b106a8b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76"
    family = "unknown"
    file_name = "b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:50:28"
  condition:
    hash.sha256(0, filesize) == "b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76"
}
```

### Sample 47: `24abb4702809d350`

| Field | Value |
|---|---|
| SHA-256 | `24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160` |
| Family label | `unknown` |
| File name | `24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160.exe` |
| File type | `exe` |
| First seen | `2026-10-07 01:49:55` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7baec9e0a38ba52d7a8a545e9dbf6c9` |
| SHA-1 | `e801aebe9b49a6af5f8f8ee5ac9a999ac4290b4c` |
| SHA-256 | `24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160` |
| SHA3-384 | `6ac4e5693a70d1804ae0317044f98161beecec839bf6c59b05bde034e7f0185dbc660e1e0f80791ccb0e92c26b4df660` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T11BA6F71B328414DCCA8BC27548F45D7D17F23DBE5623B68E0BA9BB942F127956F24E08` |
| SSDEEP | `49152:z1Uv2OB/aVJCKo66c8HZtRuXC+OKo8+GO3gf43cDzHF:yxaGsdZqbMN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_24abb470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160"
    family = "unknown"
    file_name = "24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:49:55"
  condition:
    hash.sha256(0, filesize) == "24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160"
}
```

### Sample 48: `ffce7a3896c7e9e8`

| Field | Value |
|---|---|
| SHA-256 | `ffce7a3896c7e9e8172737d45c1eaed7f62b0a09b65ce22c5eeff9f25b7ace9d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-07 01:39:14` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05f8f93fb8a821aade444de558350595` |
| SHA-1 | `a50e101f97d2b8a3be2e7a70cf1d0861bb7b48c0` |
| SHA-256 | `ffce7a3896c7e9e8172737d45c1eaed7f62b0a09b65ce22c5eeff9f25b7ace9d` |
| SHA3-384 | `894716d6a7dc86d6f8a9ae91ba4e1c7d63013f0464b06db89b2b3f8ee678690ce45822947b8938d83218a84bd4e0d5ed` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T19CA5231227D260B2EDB44BB2D4F74B93C236B4E66E785A8F2788444F1E729C4693171F` |
| SSDEEP | `49152:lXNQlj2FwDS72vwURN26b5fyQnzHSqy3QS0Os:VNQle3ARvb5fbnztyH0O` |
| ICON-DHASH | `3b3f273b379d99d2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_ffce7a38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffce7a3896c7e9e8172737d45c1eaed7f62b0a09b65ce22c5eeff9f25b7ace9d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 01:39:14"
  condition:
    hash.sha256(0, filesize) == "ffce7a3896c7e9e8172737d45c1eaed7f62b0a09b65ce22c5eeff9f25b7ace9d"
}
```

### Sample 49: `0730cfb40dfc49e8`

| Field | Value |
|---|---|
| SHA-256 | `0730cfb40dfc49e8b00344d72312c96832330b214c011d40fa338f3da2c84124` |
| Family label | `unknown` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-10-07 01:10:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9e33911ebc24b91cc356f46cdb429fc` |
| SHA-1 | `111837f765c413e6b1bd327ad99ed46168e879e5` |
| SHA-256 | `0730cfb40dfc49e8b00344d72312c96832330b214c011d40fa338f3da2c84124` |
| SHA3-384 | `e8995f765894871a93a8cced8357aa2104d04b3430d675b6937273d603144f043090d35500d89b17d61291ed5f9fcdd2` |
| TLSH | `T19D565C81FB489129E94B0B324C630F74B3605D85C1E4996B4706F76F0AB36F66A8FED4` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:MUav0adTrjYFU+QzVFf/20fZ1sQJFn4jE8:5cwCfjhXnj8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_0730cfb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0730cfb40dfc49e8b00344d72312c96832330b214c011d40fa338f3da2c84124"
    family = "unknown"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-07 01:10:30"
  condition:
    hash.sha256(0, filesize) == "0730cfb40dfc49e8b00344d72312c96832330b214c011d40fa338f3da2c84124"
}
```

### Sample 50: `cff2863f1c2f4c08`

| Field | Value |
|---|---|
| SHA-256 | `cff2863f1c2f4c0800f43bf600f2107cee2b3e5df7591f58462190a8aa3993f9` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-07 01:02:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fb626c9a03178472001ccde5c2470c4` |
| SHA-1 | `a0fedbb8f6db291a6f3393fc2d6e2d1eb4e35377` |
| SHA-256 | `cff2863f1c2f4c0800f43bf600f2107cee2b3e5df7591f58462190a8aa3993f9` |
| SHA3-384 | `7115038b2d49e284a421c4d0f0142db24f1132d8918c2601db3c0a9b0362caee92fb2021b372ed6c74bea709c81f3718` |
| TLSH | `T155A52A6FB8429E42C4D465FAF9BD81D8334753B8C2DAB116EA05CB3439DF84A4E39B44` |
| TELFHASH | `t198a002f63ccedef5b79914a5115e041cab3d8f2ea91e001c42288d3d9ca00cf7190057` |
| SSDEEP | `24576:q+OGlnZQuNz3sanIUTxs1bjYuxAR3HJ9pbusMZnyi+N2tkJYV31:q+BnZbTuxAR3p9husMlyi+u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_cff2863f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cff2863f1c2f4c0800f43bf600f2107cee2b3e5df7591f58462190a8aa3993f9"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-07 01:02:20"
  condition:
    hash.sha256(0, filesize) == "cff2863f1c2f4c0800f43bf600f2107cee2b3e5df7591f58462190a8aa3993f9"
}
```

### Sample 51: `2c75acfa406e571b`

| Field | Value |
|---|---|
| SHA-256 | `2c75acfa406e571ba0898b6e648209afd620caa782a73f8150fbc0412c099bc8` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-07 00:57:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18b319de364e09d9184ad236ad2d58d5` |
| SHA-1 | `ac1503acab77e6c4cf7d4f747cfe533f4c6c80c4` |
| SHA-256 | `2c75acfa406e571ba0898b6e648209afd620caa782a73f8150fbc0412c099bc8` |
| SHA3-384 | `750c5dd93a3d126f697fa563a5d0ffb190515e5b4f0b22dda29d2dcfd802d0da1c4d674427bf63fdddd96cc2ff05065c` |
| TLSH | `T1D8D45D66BD919B90C5E259BEFB9E437872035BB9E3FFB106CA045F906BC54850B3E201` |
| SSDEEP | `12288:obPSsT5FOuPMCz8SJcE7SynaHGWiFLDe74VhG53hPbUx:QXMC4JWSm4Pb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_2c75acfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c75acfa406e571ba0898b6e648209afd620caa782a73f8150fbc0412c099bc8"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-07 00:57:47"
  condition:
    hash.sha256(0, filesize) == "2c75acfa406e571ba0898b6e648209afd620caa782a73f8150fbc0412c099bc8"
}
```

### Sample 52: `64b9e5ee8f6e01bc`

| Field | Value |
|---|---|
| SHA-256 | `64b9e5ee8f6e01bc1c7fff904ceaa5592d01b037afcf7b7007d2e2b00a81143c` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-10-07 00:50:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0648812be1b2d328f4997b0db4ebc847` |
| SHA-1 | `0ede89bef32392b031adb504ddfb3d93f9d3c6c2` |
| SHA-256 | `64b9e5ee8f6e01bc1c7fff904ceaa5592d01b037afcf7b7007d2e2b00a81143c` |
| SHA3-384 | `ab09c191e56f2203bfe74548bf5e6e6a4f69c58ded12364de06eba22ab2892872676c8dc62ef8742ce4576c91ac1077c` |
| TLSH | `T1FF334B42322C0F17C0A35974252F5BE487FFFAD122E4F685251F8B668A78E371489E9D` |
| SSDEEP | `768:3SjbGSLlRrYj0a8C/dQOhPC/+I20Ja6ZZ+GwPS4yns96BktDgIPi8Twl:ivW3jdQGqt7Y+Z+zN9cGgI6bl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_64b9e5ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64b9e5ee8f6e01bc1c7fff904ceaa5592d01b037afcf7b7007d2e2b00a81143c"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-07 00:50:26"
  condition:
    hash.sha256(0, filesize) == "64b9e5ee8f6e01bc1c7fff904ceaa5592d01b037afcf7b7007d2e2b00a81143c"
}
```

### Sample 53: `dfc2b462b12a6f87`

| Field | Value |
|---|---|
| SHA-256 | `dfc2b462b12a6f87dd8880222a8eff713317ace50b7f393923b3b44f7c2a26ea` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-10-07 00:49:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9103707414b3587425b802c2813c92dc` |
| SHA-1 | `24c546a320a2630df8482ecc8576c1686cb37b4f` |
| SHA-256 | `dfc2b462b12a6f87dd8880222a8eff713317ace50b7f393923b3b44f7c2a26ea` |
| SHA3-384 | `5c54851f2b505b5fc2334e6ffb23b4a6811cc4312b31a63932e7ee583563d385de0d733653d12684afc2d5bd06f2a4f1` |
| TLSH | `T1CFA2D025D345AFF8DFAF9D9053C1C2C276F543C6278AC8E340EEAF016916046BB88D59` |
| SSDEEP | `384:m/JywWc84Tp2YshxqlDeAkSqjGJLeCE5zRW6C58EM4uVcqgw05VxJm:mRxsSVsMD6xiJJE5zRWNOb4uVcqgw09o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_dfc2b462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfc2b462b12a6f87dd8880222a8eff713317ace50b7f393923b3b44f7c2a26ea"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-07 00:49:26"
  condition:
    hash.sha256(0, filesize) == "dfc2b462b12a6f87dd8880222a8eff713317ace50b7f393923b3b44f7c2a26ea"
}
```

### Sample 54: `260645ee1178499f`

| Field | Value |
|---|---|
| SHA-256 | `260645ee1178499fe369898f91ed54969e1c83358e343f9e64bc88aae58ff1cb` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm7` |
| File type | `elf` |
| First seen | `2026-10-07 00:37:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8129af8d45c76d233d15a515aaf3cc68` |
| SHA-1 | `b711255c4ab7ef3ad8016e2ef9d9e9bd5711e511` |
| SHA-256 | `260645ee1178499fe369898f91ed54969e1c83358e343f9e64bc88aae58ff1cb` |
| SHA3-384 | `f005182cfddfe9a33ae27363a1a6fc753b24ea7ffc15f8bc1555d5ad839a4d14e6d650acb85ebd7d9af733c639b8a6a6` |
| TLSH | `T13CF3F846B9829F15D5C722FEFA9F415833536BACE3FE7102D9205F6023CA69B0B63152` |
| TELFHASH | `t166d097010c1811f462a9024082af031ecd66a0ab130c4423d2d627ec9fc3382340a807` |
| SSDEEP | `3072:7OwkkgGVzE95rlCtNrpck0AhT4MHukaxQHOCasxGJA+Qet+FC:7s6NrCkFhTpOkaxQHOCaGR+5t+FC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_260645ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "260645ee1178499fe369898f91ed54969e1c83358e343f9e64bc88aae58ff1cb"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-10-07 00:37:16"
  condition:
    hash.sha256(0, filesize) == "260645ee1178499fe369898f91ed54969e1c83358e343f9e64bc88aae58ff1cb"
}
```

### Sample 55: `cc85c7eff50e4df1`

| Field | Value |
|---|---|
| SHA-256 | `cc85c7eff50e4df105b28b300fae9603ad3d1653408c6bdc5a2665a16c379103` |
| Family label | `unknown` |
| File name | `macho_cc85c7eff50e.bin` |
| File type | `macho` |
| First seen | `2026-10-07 00:14:00` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d9829d26b9a59a1e11db1b391122f44` |
| SHA-1 | `1b5bd3526243b87e211e56d95e53394bf038fc3b` |
| SHA-256 | `cc85c7eff50e4df105b28b300fae9603ad3d1653408c6bdc5a2665a16c379103` |
| SHA3-384 | `979811b23fc93b2fbd7a9ab6456a22db7be14597e92ee70c97148121890126d27478ada5bfd1bc3efa4de3226fb4bb36` |
| TLSH | `T1F5350141CE6584E6F0CCD6343A2B5B338B607570855912CBB7911E989E3A3E3F19B36B` |
| SSDEEP | `24576:FGeZfoDgdSX0cMecEtlBp1pHpFc15OjgNk5EKKGAqNLxn0:FjMLX0cR1XtpHpWwv5EKjDFy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_cc85c7ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc85c7eff50e4df105b28b300fae9603ad3d1653408c6bdc5a2665a16c379103"
    family = "unknown"
    file_name = "macho_cc85c7eff50e.bin"
    file_type = "macho"
    first_seen = "2026-10-07 00:14:00"
  condition:
    hash.sha256(0, filesize) == "cc85c7eff50e4df105b28b300fae9603ad3d1653408c6bdc5a2665a16c379103"
}
```

### Sample 56: `cb1c3496202d7eb1`

| Field | Value |
|---|---|
| SHA-256 | `cb1c3496202d7eb1803dc24fbecc332a245b52878084c1af23c2cca3ea52de09` |
| Family label | `Mirai` |
| File name | `kworker` |
| File type | `elf` |
| First seen | `2026-10-07 00:09:00` |
| Reporter | `adliwahid` |
| Tags | `Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46ddd71846daaee1200e7036d995c08d` |
| SHA-1 | `ad0267dd696b030b4078f38be82f5f1ba74b673f` |
| SHA-256 | `cb1c3496202d7eb1803dc24fbecc332a245b52878084c1af23c2cca3ea52de09` |
| SHA3-384 | `349611ad48d14843502ea063dd80e1b957db82db5dc223243a7589fd8a70e261c08738b479642f1f68f5b56d67b08874` |
| TLSH | `T1CEF3F8CCE865476FC6D327BAF649528F33321B78938BF32159A7EAB41BC17481938191` |
| TELFHASH | `t12221310362bd8b296bb64924ac7c03f119551a23b2813f70ff5ec2c0553704aa965d9f` |
| SSDEEP | `3072:GVIjgRsJGMPeuQ8oGM+AL1r9PDv1ZpYZsW1zmLmS44hzkj0ILngGMuDqc7wbEHKO:Z+bEHzqa4J+acbRmRrI+Wm+WusQ6zy5/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_cb1c3496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb1c3496202d7eb1803dc24fbecc332a245b52878084c1af23c2cca3ea52de09"
    family = "Mirai"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-10-07 00:09:00"
  condition:
    hash.sha256(0, filesize) == "cb1c3496202d7eb1803dc24fbecc332a245b52878084c1af23c2cca3ea52de09"
}
```

### Sample 57: `1ebbe1479d2be9b5`

| Field | Value |
|---|---|
| SHA-256 | `1ebbe1479d2be9b5ddae584a2d987e5f6f4ce14c1f002bb8bd1fb7e13046969e` |
| Family label | `unknown` |
| File name | `macho_1ebbe1479d2b.bin` |
| File type | `macho` |
| First seen | `2026-10-07 00:04:24` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67a7fdaf6c46f90c004ad77db60ec6bc` |
| SHA-1 | `d980b6bf10e51486ece71d024a3d86d0a7f03ba3` |
| SHA-256 | `1ebbe1479d2be9b5ddae584a2d987e5f6f4ce14c1f002bb8bd1fb7e13046969e` |
| SHA3-384 | `b0b068a96570112cb1496f44e35864b5680ea91ec715a9c72cc838064f2f4987f748ec3d555fe9e9476a362837f286f9` |
| TLSH | `T1AC45F1019F6164A6F58CDE343F2B4ABB5E60B230844D55DB6B921A68CD313D3F0A636F` |
| SSDEEP | `24576:zvxOyw02Au8ULgmrttFmRUGsag2AyO8n4a5G:LxJ6bgmrXFGU/G54a5G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_1ebbe147
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ebbe1479d2be9b5ddae584a2d987e5f6f4ce14c1f002bb8bd1fb7e13046969e"
    family = "unknown"
    file_name = "macho_1ebbe1479d2b.bin"
    file_type = "macho"
    first_seen = "2026-10-07 00:04:24"
  condition:
    hash.sha256(0, filesize) == "1ebbe1479d2be9b5ddae584a2d987e5f6f4ce14c1f002bb8bd1fb7e13046969e"
}
```

### Sample 58: `be2c28842c350d43`

| Field | Value |
|---|---|
| SHA-256 | `be2c28842c350d43d2b3ca8822221164e190d0594be464ef80bff87c8f352207` |
| Family label | `Mirai` |
| File name | `ntp` |
| File type | `elf` |
| First seen | `2026-10-06 23:53:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `211cb081b81838f0c67de34e0aac4d73` |
| SHA-1 | `33c231c314f880e40f4918cccf7c4a1a56d16b0a` |
| SHA-256 | `be2c28842c350d43d2b3ca8822221164e190d0594be464ef80bff87c8f352207` |
| SHA3-384 | `6a97ef66841273d186b0308542727a2d9e3f1715b54f052fa1467bb203f3cb8cd237a173220021d5033f0078f661d01a` |
| TLSH | `T18B0474ADEBA19EB7D80ECD3385994503108C957A12D9AB6FB2F6C518E387C4E08D3DD4` |
| TELFHASH | `t119212e42627e8e293ff249249cac07b129566522b2807f70ef6ec2c01537009b969d9f` |
| SSDEEP | `3072:CXO/Ar3n2QGu3kizqLiNADKpSIeZ8tjTl5:WbrGQGWRmLieDKpSIeZ8tjTl5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_be2c2884
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be2c28842c350d43d2b3ca8822221164e190d0594be464ef80bff87c8f352207"
    family = "Mirai"
    file_name = "ntp"
    file_type = "elf"
    first_seen = "2026-10-06 23:53:15"
  condition:
    hash.sha256(0, filesize) == "be2c28842c350d43d2b3ca8822221164e190d0594be464ef80bff87c8f352207"
}
```

### Sample 59: `74f3d4e41fcb7a41`

| Field | Value |
|---|---|
| SHA-256 | `74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7` |
| Family label | `Mirai` |
| File name | `74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7` |
| File type | `elf` |
| First seen | `2026-10-06 23:32:17` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b7004cef67ccbca7eabc2f5f1d3eb1f` |
| SHA-1 | `bff5d7d5bf6ff5e46e2ac58480cf36f6171c38d9` |
| SHA-256 | `74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7` |
| SHA3-384 | `37ee277717f0aca0df6851d22ecdd8e1def9fd95f4ff829759100c88dad1f3596ed9cd9bf3620c320d8d285627c825e8` |
| TLSH | `T1CE358D1AB2F3F6BCD007C03097DFC6A24531F0756A312D7B26C49A392EA6DE51369B25` |
| TELFHASH | `t143117a314b6155264792cd44dcde6363212dca6a9b0dfeb7ea704a4c21050fed93bc8f` |
| SSDEEP | `24576:+9TKE4ICUYygUvpgbENg916rThFr7MJlePHauQ4fWo1:fbENg91sX7MS7f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_74f3d4e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7"
    family = "Mirai"
    file_name = "74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7"
    file_type = "elf"
    first_seen = "2026-10-06 23:32:17"
  condition:
    hash.sha256(0, filesize) == "74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7"
}
```

### Sample 60: `18cf4d150e2e3826`

| Field | Value |
|---|---|
| SHA-256 | `18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f` |
| Family label | `Mirai` |
| File name | `18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f` |
| File type | `elf` |
| First seen | `2026-10-06 23:23:27` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b440de65a0707fb9e551048b50a5f341` |
| SHA-1 | `6d8cee706d5a9c72b564389f0632e610a8129a72` |
| SHA-256 | `18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f` |
| SHA3-384 | `dbd3dd82093310bc89333d7fad95d324548626dd5c3c9a7bcf73c7e6834711664678ab08755448ba0d1b980518965eb0` |
| TLSH | `T18A357D1AB2F3F6BCD007C0309BDFC6A24531F07569312D7B26C49A392EA6DE51369B25` |
| TELFHASH | `t143117a314b6155264792cd44dcde6363212dca6a9b0dfeb7ea704a4c21050fed93bc8f` |
| SSDEEP | `24576:8C0Ka4rydaCQEJJ1OENg3VNeqFStCwuf36INstWo1:IOENg3VSt60t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_18cf4d15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f"
    family = "Mirai"
    file_name = "18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f"
    file_type = "elf"
    first_seen = "2026-10-06 23:23:27"
  condition:
    hash.sha256(0, filesize) == "18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f"
}
```

### Sample 61: `c027df0ed143719a`

| Field | Value |
|---|---|
| SHA-256 | `c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041` |
| Family label | `Mirai` |
| File name | `c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041` |
| File type | `elf` |
| First seen | `2026-10-06 23:03:00` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1fcf72c6e677cbd2f937ecf2a3b4b96` |
| SHA-1 | `76e617e6ae06ea9732460b5dbe56dc902f5760a7` |
| SHA-256 | `c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041` |
| SHA3-384 | `460c7354a7848a4a56bedd415646c52c93c956c2012b0f581bc8b0f735a21be0e1b95a970d43d232f45123907aeb36ec` |
| TLSH | `T12D358C1AB2F3F6BCD007C03097DFC6A24531F0756A312D7F26C49A392EA6DA51369B25` |
| TELFHASH | `t143117a314b6155264792cd44dcde6363212dca6a9b0dfeb7ea704a4c21050fed93bc8f` |
| SSDEEP | `24576:Q9TKE4ICvnygUvpgbENg916rThFr7MJlePHau/AfWo1:dbENg91sX7MSIf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_c027df0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041"
    family = "Mirai"
    file_name = "c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041"
    file_type = "elf"
    first_seen = "2026-10-06 23:03:00"
  condition:
    hash.sha256(0, filesize) == "c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041"
}
```

### Sample 62: `cbcefa22c0ff043f`

| Field | Value |
|---|---|
| SHA-256 | `cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642` |
| Family label | `Mirai` |
| File name | `cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642` |
| File type | `elf` |
| First seen | `2026-10-06 22:32:47` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d789255bd1ee435db07e4008e0a3bf8e` |
| SHA-1 | `b4f5c772352bcc625752a70415b8a40eb6619db1` |
| SHA-256 | `cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642` |
| SHA3-384 | `6179b233b92a861d40eaa30818e4c8027ced43f3f92b84c8fc97017d42a301683463c9165e471395bf76a0cdcc467728` |
| TLSH | `T1D6358D1AB2B3B6BCD007C0305BDFC6A24531F07569322D7B26C4DB352EA6DE5136AB25` |
| TELFHASH | `t143117a314b6155264792cd44dcde6363212dca6a9b0dfeb7ea704a4c21050fed93bc8f` |
| SSDEEP | `24576:OpHYYu4346up14l6hxAeNg8pnnAEhT48Q7Ui2FeTWo1:7AeNg8pBhkohAT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_cbcefa22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642"
    family = "Mirai"
    file_name = "cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642"
    file_type = "elf"
    first_seen = "2026-10-06 22:32:47"
  condition:
    hash.sha256(0, filesize) == "cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642"
}
```

### Sample 63: `fa2384bd1fe35beb`

| Field | Value |
|---|---|
| SHA-256 | `fa2384bd1fe35beb69afa1289e4856b015a9f822c4c8fc5acfdafa82b47aa94c` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-10-06 22:32:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06f8a7b518e0d42375db6032b9ed1fcf` |
| SHA-1 | `2280a455eb5c546370cb3a7722994c42be4ea77b` |
| SHA-256 | `fa2384bd1fe35beb69afa1289e4856b015a9f822c4c8fc5acfdafa82b47aa94c` |
| SHA3-384 | `88727dd7a097362bccd38232fa9e6dd9c74ca3e0650c2fa954a1b341f6a81856f2167fc46b4ba2c1b747f6482c6f0df7` |
| TLSH | `T159733A91BC815B13C6D022BBFB5E428E372653A8D2EE72179D226F1137C785B0E77641` |
| TELFHASH | `t11e51c9976bb10edc17e0c35083c9a93a8aed34d91b1435aac75d2b9f8487ec2745a435` |
| SSDEEP | `1536:7BxiqP7YhGCz7ydCjmw13t2AgPSnJz28OBngzs/h7:9xJ0rBp13wKnfI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_fa2384bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa2384bd1fe35beb69afa1289e4856b015a9f822c4c8fc5acfdafa82b47aa94c"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-10-06 22:32:42"
  condition:
    hash.sha256(0, filesize) == "fa2384bd1fe35beb69afa1289e4856b015a9f822c4c8fc5acfdafa82b47aa94c"
}
```

### Sample 64: `20d4672f40c452d5`

| Field | Value |
|---|---|
| SHA-256 | `20d4672f40c452d53b41227f669c481703677e302954c52158515f7003d2fb27` |
| Family label | `Gafgyt` |
| File name | `telnet` |
| File type | `elf` |
| First seen | `2026-10-06 22:32:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49146711fd692c0855ed8717b11beaab` |
| SHA-1 | `4d0cc5b0bc1aea41b38d1c2e35e9cf1d0bdc7ed9` |
| SHA-256 | `20d4672f40c452d53b41227f669c481703677e302954c52158515f7003d2fb27` |
| SHA3-384 | `a55b0a980765f05c030fb829358a23a4ee156b6dc83a103d9ffee579822825b101a28290ab8b8b29482690bfa46ed691` |
| TLSH | `T1A7E3E5CCFD64476FC2D223BAF74A428F37261A789797F32159A7E9B02BC17481D28191` |
| TELFHASH | `t119212e42627e8e293ff249249cac07b129566522b2807f70ef6ec2c01537009b969d9f` |
| SSDEEP | `3072:qklR8BGM3+mgYwGMyZRgi8KGqiPc+k3WL7tX8h3GbF2lLothTpKkxnwjUly8CTlR:xnaUszTAYowcnaFD6knQCquS5hA5` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_064_20d4672f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20d4672f40c452d53b41227f669c481703677e302954c52158515f7003d2fb27"
    family = "Gafgyt"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-10-06 22:32:40"
  condition:
    hash.sha256(0, filesize) == "20d4672f40c452d53b41227f669c481703677e302954c52158515f7003d2fb27"
}
```

### Sample 65: `cd3158bdde5b7145`

| Field | Value |
|---|---|
| SHA-256 | `cd3158bdde5b7145a69e72579fb14577c0f8eb1e49de549968a8ecbf6c3c4701` |
| Family label | `unknown` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-06 22:32:23` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41943a34fd0115c01bddf99f57b1dbf7` |
| SHA-1 | `a9ee679dbd1cd29ed6050b058fb739cdbb62ed99` |
| SHA-256 | `cd3158bdde5b7145a69e72579fb14577c0f8eb1e49de549968a8ecbf6c3c4701` |
| SHA3-384 | `5a145f7ed7b02f5b213c88d31e361e6144610fd9ef0b6c7eb724145176d4a2d5457cd80a400839526099180ad520864f` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T10BD62917728800DCC94BD67584B41D7A12B13DEE5532BB8E0E99BE902F177996FACF08` |
| SSDEEP | `49152:LEJtOrWW+vA/uahu/kPeLj1TJQiO9+PIdlq+U4Ypf3YHdMqcq2s3vnfSQYYq/qvj:uAW3OboVcSxykyv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_cd3158bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd3158bdde5b7145a69e72579fb14577c0f8eb1e49de549968a8ecbf6c3c4701"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-06 22:32:23"
  condition:
    hash.sha256(0, filesize) == "cd3158bdde5b7145a69e72579fb14577c0f8eb1e49de549968a8ecbf6c3c4701"
}
```

### Sample 66: `243d7d7c79cccb57`

| Field | Value |
|---|---|
| SHA-256 | `243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c` |
| Family label | `Mirai` |
| File name | `243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c` |
| File type | `sh` |
| First seen | `2026-10-06 22:08:38` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `313d4a5d2675ddc14e593470cd219230` |
| SHA-1 | `7c6bf881210bdb347fb9e53b7516beae3e138eb1` |
| SHA-256 | `243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c` |
| SHA3-384 | `8910a30461b7bc6772d29538e4bd395e4769122fa60a2caa83386cf4292948f6cc10a60446b1bc045cbb92451766eb47` |
| TLSH | `T1D131F0E57172E6BBB8A581BCB2879A30380440EB0C44AA7D344E9B701F8D74CB1657AD` |
| SSDEEP | `24:ieP4hrSvQu/fFkdmkhIYnSZVcuw5MMTWZVMSq8jO457YLI3cpHq6ps:pQhrSYulImkyYSfcTezfMSq8jJ57YLI3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_243d7d7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c"
    family = "Mirai"
    file_name = "243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c"
    file_type = "sh"
    first_seen = "2026-10-06 22:08:38"
  condition:
    hash.sha256(0, filesize) == "243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c"
}
```

### Sample 67: `e74072e835179517`

| Field | Value |
|---|---|
| SHA-256 | `e74072e835179517a8591dab94f3e9375289318fe680840e61503b9c04336666` |
| Family label | `Mirai` |
| File name | `ntpd` |
| File type | `elf` |
| First seen | `2026-10-06 21:56:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc71d311b38ee76b7c75a46eb831a93e` |
| SHA-1 | `3b7bf4ed75d355e17a35dbbbaa37ab0057bb09df` |
| SHA-256 | `e74072e835179517a8591dab94f3e9375289318fe680840e61503b9c04336666` |
| SHA3-384 | `27f8213d61d420d922e5c8af773341932691403ed351ba50a5de2e2b00c2ec79358644a93637abcdb953fe3bede3a705` |
| TLSH | `T186D318DFF2D0CAFAC446A1B1DADB8553E412FA380622E20733D3FD652A2D5C85D592C2` |
| TELFHASH | `t136213542627d8e297fb24924acac07f11956152372407f70ff5ec1c4653b009b575d8f` |
| SSDEEP | `3072:9nQpvQDG9HBykwzITRXsCrdrA8Ej8Njq6MlDbcZ4crd7yh+:xQpvQDG9/wzmxrdMLrzlDbcZ4crd7yh+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_e74072e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e74072e835179517a8591dab94f3e9375289318fe680840e61503b9c04336666"
    family = "Mirai"
    file_name = "ntpd"
    file_type = "elf"
    first_seen = "2026-10-06 21:56:32"
  condition:
    hash.sha256(0, filesize) == "e74072e835179517a8591dab94f3e9375289318fe680840e61503b9c04336666"
}
```

### Sample 68: `5ec4c1ecaf67ba48`

| Field | Value |
|---|---|
| SHA-256 | `5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704` |
| Family label | `WannaCry` |
| File name | `5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704` |
| File type | `exe` |
| First seen | `2026-10-06 21:15:41` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d77b96fe72bfd13d513ab559cba4b308` |
| SHA-1 | `d3fd6ee9651ff08f2cd0a945365bd5b984f7cb54` |
| SHA-256 | `5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704` |
| SHA3-384 | `4c625fa8470148e05ea496262295ea4233704018e4e67d0d9a7ccf06280de8130ec981244c31d47c061e2541b6225c5d` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T12936334972A891FCD0050A7884B78E57B3F37C5A67FA4B0F4B80866B0D53B46EFA4742` |
| SSDEEP | `98304:DI8qPoBhz1aRxcSUDk36SAEdhvK3R8yAVp2H:DI8qPe1Cxcxk3ZAEoR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_068_5ec4c1ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704"
    family = "WannaCry"
    file_name = "5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704"
    file_type = "exe"
    first_seen = "2026-10-06 21:15:41"
  condition:
    hash.sha256(0, filesize) == "5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704"
}
```

### Sample 69: `0fad00ddec16b67f`

| Field | Value |
|---|---|
| SHA-256 | `0fad00ddec16b67f3131aa4efffbe32d78fca178407895920b7549667d7bbfbf` |
| Family label | `Gafgyt` |
| File name | `handshakebins.sh` |
| File type | `sh` |
| First seen | `2026-10-06 21:09:05` |
| Reporter | `abuse_ch` |
| Tags | `Gafgyt, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0126a389136ade4b080af553900fd84e` |
| SHA-1 | `0e5533113cef49b8faaf283240760a601efa614f` |
| SHA-256 | `0fad00ddec16b67f3131aa4efffbe32d78fca178407895920b7549667d7bbfbf` |
| SHA3-384 | `f1e8d59fda1a9240bd117250d2e81ebe199ac142d35c1966fec6f55e06552523047469b6a2d99179c133de5d3cc9987d` |
| TLSH | `T156E1C3D721A708702DE0E82B72BB5C0475E9A59F40E6AF896EEC3CF951CDD48B090793` |
| SSDEEP | `96:Gvf+srLjrzrHCKxJDUWgyQEol8fHn4El2KxiX1Dl8pPeOKx+mqcl8z:juGL5l8wEAjDl8pPbzcl8z` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_069_0fad00dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fad00ddec16b67f3131aa4efffbe32d78fca178407895920b7549667d7bbfbf"
    family = "Gafgyt"
    file_name = "handshakebins.sh"
    file_type = "sh"
    first_seen = "2026-10-06 21:09:05"
  condition:
    hash.sha256(0, filesize) == "0fad00ddec16b67f3131aa4efffbe32d78fca178407895920b7549667d7bbfbf"
}
```

### Sample 70: `64b9c6000e30cd09`

| Field | Value |
|---|---|
| SHA-256 | `64b9c6000e30cd09d2f81b418df20e1ff916fc0e34100df262830c8d15ba4cd8` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-06 20:55:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c40e83d7f6430c4aa70ea5041f24d8f7` |
| SHA-1 | `9d8f79ac112d709b9887bbbbd4368904bd9bf14c` |
| SHA-256 | `64b9c6000e30cd09d2f81b418df20e1ff916fc0e34100df262830c8d15ba4cd8` |
| SHA3-384 | `754d8da99d0624452dfc494e7f72f316e391a4db6a7b5223871fc04ae75a8571c2af8ad4312c9f66181014e21d551f8e` |
| TLSH | `T191D47E8BB650DDBEF886D33644130B296020F2E245E29B6FF15F7DA4EB2D1902535BC6` |
| SSDEEP | `6144:UBbHIxDcUKogZB0jdf4/bfQyZg8W8XAlT5hSzhuwyjGJtpWbDm977LZHutLKdex:WDIxoqzjC/DdC8MTZdDQHut2dex` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_64b9c600
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64b9c6000e30cd09d2f81b418df20e1ff916fc0e34100df262830c8d15ba4cd8"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-06 20:55:29"
  condition:
    hash.sha256(0, filesize) == "64b9c6000e30cd09d2f81b418df20e1ff916fc0e34100df262830c8d15ba4cd8"
}
```

### Sample 71: `daeb4dddaefa21f1`

| Field | Value |
|---|---|
| SHA-256 | `daeb4dddaefa21f1e952b3a3e606f91d7c95955db3458730d30a0a218d005246` |
| Family label | `Gafgyt` |
| File name | `telnet` |
| File type | `elf` |
| First seen | `2026-10-06 20:40:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b8076a618c9f7a3e4cb54ba45408913` |
| SHA-1 | `219b6d066cd83f2fec210bb52e5842e4362e13a2` |
| SHA-256 | `daeb4dddaefa21f1e952b3a3e606f91d7c95955db3458730d30a0a218d005246` |
| SHA3-384 | `4f7402bee98ce2b2883461efbfab36cd639ab08bb911fe9e1e93e4674c8309691cb4cc9d73b31ede42cb9c7fb155c60c` |
| TLSH | `T1DDE3F4CCFD64476FC2C223BAF749428F37261A78979BF32159A7E9B02BC57481D28191` |
| TELFHASH | `t119212e42627e8e293ff249249cac07b129566522b2807f70ef6ec2c01537009b969d9f` |
| SSDEEP | `3072:kklR8BGM3+mgYwGMyaRgi8KGqiPc+k3WL7tX8h3GbF2lLothTpKkinzrVoyuz0DL:HzrV7S0YWBNcnExD6knQCquS5hA5` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_071_daeb4ddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daeb4dddaefa21f1e952b3a3e606f91d7c95955db3458730d30a0a218d005246"
    family = "Gafgyt"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-10-06 20:40:37"
  condition:
    hash.sha256(0, filesize) == "daeb4dddaefa21f1e952b3a3e606f91d7c95955db3458730d30a0a218d005246"
}
```

### Sample 72: `b98a0909267bca4d`

| Field | Value |
|---|---|
| SHA-256 | `b98a0909267bca4d6296b544d4463e00f28f38099dd4504df1c6cdeac15a760f` |
| Family label | `Mirai` |
| File name | `kernal` |
| File type | `elf` |
| First seen | `2026-10-06 20:35:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19a4912dc318361df0427dc32bdd05f4` |
| SHA-1 | `8de8fd2fe989979856e7ab0259fc57e0bab0ff79` |
| SHA-256 | `b98a0909267bca4d6296b544d4463e00f28f38099dd4504df1c6cdeac15a760f` |
| SHA3-384 | `6eccbdc43d7ac18ccecc219b904acf3feb3aca3d5abf5f0c38c96dd8a4257196a2b71c397d48e4a8e3425a2daf8f68fe` |
| TLSH | `T1E4D309CEF801DE7AF50AA63AC8C30A17B270BB750A52D62572C7F96699331D43426FC5` |
| TELFHASH | `t119212e42627e8e293ff249249cac07b129566522b2807f70ef6ec2c01537009b969d9f` |
| SSDEEP | `3072:OSp4uKxGyK0srgRfTYL4u1XwiyMzPbqzD7JoYWBthL15:J4uYzKQLYL91jyMnqzD7JoYWBthL15` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_b98a0909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98a0909267bca4d6296b544d4463e00f28f38099dd4504df1c6cdeac15a760f"
    family = "Mirai"
    file_name = "kernal"
    file_type = "elf"
    first_seen = "2026-10-06 20:35:53"
  condition:
    hash.sha256(0, filesize) == "b98a0909267bca4d6296b544d4463e00f28f38099dd4504df1c6cdeac15a760f"
}
```

### Sample 73: `0cd4604de3284d71`

| Field | Value |
|---|---|
| SHA-256 | `0cd4604de3284d716488b41fe24760b3375f116651d1e7a325736de8950c196e` |
| Family label | `unknown` |
| File name | `Текст Договора - версия 3.lnk` |
| File type | `lnk` |
| First seen | `2026-10-06 20:25:56` |
| Reporter | `smica83` |
| Tags | `lnk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a2370412e4564e7364e48bec5cb4deb` |
| SHA-1 | `8f4048aedf960e33732ff7d2e37c5746dc7f5a5a` |
| SHA-256 | `0cd4604de3284d716488b41fe24760b3375f116651d1e7a325736de8950c196e` |
| SHA3-384 | `ffb992bf79d71d89accd07401e1c140c8df793f4e8c910b5fa159f123f1edd5e528040cb80d928525cb71a731f533626` |
| TLSH | `T11F41DD241BE94225D77ACD3AE869A314C97AB486DC338F0D018191840DB4619FDB1F6E` |
| SSDEEP | `24:8+166JBG9agWA2AkmDf6ERXeGwz5fegaRReGwzGOwfubjT4o028dabf0TAsm:82HJgN1dRXgggaRRgDLbjMoCa7AAs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_0cd4604d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cd4604de3284d716488b41fe24760b3375f116651d1e7a325736de8950c196e"
    family = "unknown"
    file_name = "Текст Договора - версия 3.lnk"
    file_type = "lnk"
    first_seen = "2026-10-06 20:25:56"
  condition:
    hash.sha256(0, filesize) == "0cd4604de3284d716488b41fe24760b3375f116651d1e7a325736de8950c196e"
}
```

### Sample 74: `5209aa6242215875`

| Field | Value |
|---|---|
| SHA-256 | `5209aa6242215875f7f9bccfca412a72d0fd99db10e87ee7eab113cf88628d0c` |
| Family label | `AgentTesla` |
| File name | `SKM_7209435700.js` |
| File type | `js` |
| First seen | `2026-10-06 20:21:49` |
| Reporter | `James_inthe_box` |
| Tags | `AgentTesla, exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab5104c9f3af73c6f0f2032a2c893a40` |
| SHA-1 | `599aa90d8dbdf7da51ed512ed43456f2be1d49bc` |
| SHA-256 | `5209aa6242215875f7f9bccfca412a72d0fd99db10e87ee7eab113cf88628d0c` |
| SHA3-384 | `d1c1591e4579988a713df576c24ebfc72cdfe5c06daf90595ef566a3fa3afb1d926302da7b903bbc2992005a641bc31b` |
| TLSH | `T165E4DF454A01DD90EA6AF7224B7B763F23B0C241458BD298938CC381367BB50E3BAF56` |
| SSDEEP | `12288:v8gHYHOgUQePy8FEK4+bCKnUiQeWXaA5nbUdiFuS/H2+qY826fgF5nYD:vL2ODQePyiRbR6eHAS2uSg4+` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_074_5209aa62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5209aa6242215875f7f9bccfca412a72d0fd99db10e87ee7eab113cf88628d0c"
    family = "AgentTesla"
    file_name = "SKM_7209435700.js"
    file_type = "js"
    first_seen = "2026-10-06 20:21:49"
  condition:
    hash.sha256(0, filesize) == "5209aa6242215875f7f9bccfca412a72d0fd99db10e87ee7eab113cf88628d0c"
}
```

### Sample 75: `3feed21d01cd1f34`

| Field | Value |
|---|---|
| SHA-256 | `3feed21d01cd1f34f6c9dec6e7115a94865e4e2dc76002c6ef2384e461993081` |
| Family label | `Mirai` |
| File name | `vcimanagement.mips` |
| File type | `elf` |
| First seen | `2026-10-06 20:20:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab0922552200932a4b0e077903bd21e4` |
| SHA-1 | `239ec64839984a8f1a0f2efe3bcddcc90d383967` |
| SHA-256 | `3feed21d01cd1f34f6c9dec6e7115a94865e4e2dc76002c6ef2384e461993081` |
| SHA3-384 | `008c9221033f1b1afe62d126e3262c5f7c3578845a8fd389baddff7104a1cc4fb3b5a21274fac09a76230fa518c6dd15` |
| TLSH | `T15934A75F6E228F6EF369877487F34931A75823DA16E2D640E1ACD5101F242CE641FBAC` |
| TELFHASH | `t18d41a3180d7817e0a3256c9949adff36d5a330db7f162c378a51e86ae769f834e15c0c` |
| SSDEEP | `3072:We8KmtZoiFjOiC3Rlw0y3ihi93Lqoi7jSr223t:WevuoiFje3ReSY2pjSa2d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_3feed21d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3feed21d01cd1f34f6c9dec6e7115a94865e4e2dc76002c6ef2384e461993081"
    family = "Mirai"
    file_name = "vcimanagement.mips"
    file_type = "elf"
    first_seen = "2026-10-06 20:20:48"
  condition:
    hash.sha256(0, filesize) == "3feed21d01cd1f34f6c9dec6e7115a94865e4e2dc76002c6ef2384e461993081"
}
```

### Sample 76: `e634abc411327b6c`

| Field | Value |
|---|---|
| SHA-256 | `e634abc411327b6c0f341f88838a443a227419ef1d75244fe3ce5c1596e7a0b2` |
| Family label | `Mirai` |
| File name | `gnome` |
| File type | `elf` |
| First seen | `2026-10-06 19:56:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96bfa984a8c2fb769ea1a0a6a03939d1` |
| SHA-1 | `21ade769bebc37c45d99eacbd66d37ec3757d4ff` |
| SHA-256 | `e634abc411327b6c0f341f88838a443a227419ef1d75244fe3ce5c1596e7a0b2` |
| SHA3-384 | `389290830b58fc590a4926a4859af34b72b0617c8e98b884ceca301a4a771ef5e3b07c29649e27e97ab42cbcaf89ad1c` |
| TLSH | `T14D0463BEFA11BB6EE168873187F25F72C39521B22291D341E2EED6185E7528C085F7D0` |
| TELFHASH | `t119212e42627e8e293ff249249cac07b129566522b2807f70ef6ec2c01537009b969d9f` |
| SSDEEP | `3072:gIZrG2Zf/xL4ytxzLiBKUHqeWluPDbpSIeZ8tjTl5:LZa6rGjr3PDbpSIeZ8tjTl5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_e634abc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e634abc411327b6c0f341f88838a443a227419ef1d75244fe3ce5c1596e7a0b2"
    family = "Mirai"
    file_name = "gnome"
    file_type = "elf"
    first_seen = "2026-10-06 19:56:04"
  condition:
    hash.sha256(0, filesize) == "e634abc411327b6c0f341f88838a443a227419ef1d75244fe3ce5c1596e7a0b2"
}
```

### Sample 77: `a7ec293736b98f2e`

| Field | Value |
|---|---|
| SHA-256 | `a7ec293736b98f2eb2dd24801d3b958b2c2b33553bcf975c6e654861fd86422f` |
| Family label | `unknown` |
| File name | `rooming.hta` |
| File type | `hta` |
| First seen | `2026-10-06 19:40:10` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e75e5f1f532304ac68766bebdc5f8c8b` |
| SHA-1 | `bf9ac9924eab4eea39368eb7afd66ada7f47dfbc` |
| SHA-256 | `a7ec293736b98f2eb2dd24801d3b958b2c2b33553bcf975c6e654861fd86422f` |
| SHA3-384 | `bee605f5251b34ef03725b421d4916dd1837f5ac36f1c7af518a8ab3ad7dcd0e2afc260560476d1de7764184de5c468b` |
| TLSH | `T1D942195CAED162B0EA1707DE73AF24690228A0C7240DC484F94CDDE87F46BDC4A57B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzXbqFtCASsWRUM:sXX+/DV7k/3OFt5WRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_a7ec2937
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7ec293736b98f2eb2dd24801d3b958b2c2b33553bcf975c6e654861fd86422f"
    family = "unknown"
    file_name = "rooming.hta"
    file_type = "hta"
    first_seen = "2026-10-06 19:40:10"
  condition:
    hash.sha256(0, filesize) == "a7ec293736b98f2eb2dd24801d3b958b2c2b33553bcf975c6e654861fd86422f"
}
```

### Sample 78: `f94c1aaa08179bda`

| Field | Value |
|---|---|
| SHA-256 | `f94c1aaa08179bda1d9a6be54cf159ee9e80a92fcd01e6a6ecf6dbf434f9513e` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.X97M.DownLoader.2343.12252.12934` |
| File type | `xlsx` |
| First seen | `2026-10-06 19:36:15` |
| Reporter | `SecuriteInfoCom` |
| Tags | `xlsx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `261927f5140fa0abe2f60d82e35211f4` |
| SHA-1 | `07343f01663ef050b87d60c2cfb7ee7f03f0a51d` |
| SHA-256 | `f94c1aaa08179bda1d9a6be54cf159ee9e80a92fcd01e6a6ecf6dbf434f9513e` |
| SHA3-384 | `082fdd143aec0d6d857619b7cc78a50a560fadb5b0c66724e35207963e69d4432f5ca13066213e4aecc70741c5ac8734` |
| TLSH | `T103B3F15DB16DC024D41ACC74ACC0E6EFA6133C92ED0B951B36AAF70E14BD0914E6F76A` |
| SSDEEP | `1536:iREpq7Q9U8e1vk9HOH5o5SVRc1eHIgXYTyAOoOXH49n2qc2B:izG7eCOZo5SVu1epoTyPoqHyn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xlsx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_f94c1aaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94c1aaa08179bda1d9a6be54cf159ee9e80a92fcd01e6a6ecf6dbf434f9513e"
    family = "unknown"
    file_name = "SecuriteInfo.com.X97M.DownLoader.2343.12252.12934"
    file_type = "xlsx"
    first_seen = "2026-10-06 19:36:15"
  condition:
    hash.sha256(0, filesize) == "f94c1aaa08179bda1d9a6be54cf159ee9e80a92fcd01e6a6ecf6dbf434f9513e"
}
```

### Sample 79: `f7553d5037de0393`

| Field | Value |
|---|---|
| SHA-256 | `f7553d5037de0393da84fed09eaa9908768b91044ef42c8614a8c7efac81fe7c` |
| Family label | `unknown` |
| File name | `CS2 Aether Tool.exe` |
| File type | `exe` |
| First seen | `2026-10-06 19:28:19` |
| Reporter | `nextpro` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd882a7f7d98b668b45455ebb357532f` |
| SHA-1 | `24fc3646beaa8ed473483c40547610a8c40be66b` |
| SHA-256 | `f7553d5037de0393da84fed09eaa9908768b91044ef42c8614a8c7efac81fe7c` |
| SHA3-384 | `0c70df01930c9f38c26a6d26dd6f6da715cc199332f634d6edf43c5433ecb2fc3757a97ba6cab9992e5962f8c37aac62` |
| IMPHASH | `9eba512b03d8cac8a6c4424e25e9f06e` |
| TLSH | `T19C48F01663E111AAD577D178C7AB6203EB72B40713308BDB329C43652F63AE45E7BB60` |
| SSDEEP | `1572864:1Pp36F/iKRzyo0EL9uXpXFxAI/MZqNrGZVOc4XIoC3MnluZQrZg:1PpIlyheuXpX/z/5NivOcC7hlTre` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_f7553d50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7553d5037de0393da84fed09eaa9908768b91044ef42c8614a8c7efac81fe7c"
    family = "unknown"
    file_name = "CS2 Aether Tool.exe"
    file_type = "exe"
    first_seen = "2026-10-06 19:28:19"
  condition:
    hash.sha256(0, filesize) == "f7553d5037de0393da84fed09eaa9908768b91044ef42c8614a8c7efac81fe7c"
}
```

### Sample 80: `eff4cbad70d1a0cb`

| Field | Value |
|---|---|
| SHA-256 | `eff4cbad70d1a0cbf9c296ebb2ea16e25cf52cb961b278501081bd6a376f1652` |
| Family label | `Gafgyt` |
| File name | `telnetd` |
| File type | `elf` |
| First seen | `2026-10-06 19:20:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `789a0450127a47c2ac1038b067ce1ff2` |
| SHA-1 | `67f625f223c1e66d1e4ab7f6dfb1e9c3e6ae5ea2` |
| SHA-256 | `eff4cbad70d1a0cbf9c296ebb2ea16e25cf52cb961b278501081bd6a376f1652` |
| SHA3-384 | `90fc5cbc6dbdc7f419eb0540ed82db031452d11ded1cf4b11915627cc59d4f9c1f8f09d1fe3f8b7edcb3119636342078` |
| TLSH | `T162E3E5CCFD54476FC2D223BAF75A42CF37261A789797B32159A7E9B02BC17481D281A0` |
| TELFHASH | `t119212e42627e8e293ff249249cac07b129566522b2807f70ef6ec2c01537009b969d9f` |
| SSDEEP | `3072:PklRIBGM3+mgYwGMyMRgi8KGqiPc+k3WL7tX8h3GbF2lLothTpKkUiHbEBy84cdf:4i7EIxcDI935bInx0DhT0Qs8RT57g5` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_080_eff4cbad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff4cbad70d1a0cbf9c296ebb2ea16e25cf52cb961b278501081bd6a376f1652"
    family = "Gafgyt"
    file_name = "telnetd"
    file_type = "elf"
    first_seen = "2026-10-06 19:20:17"
  condition:
    hash.sha256(0, filesize) == "eff4cbad70d1a0cbf9c296ebb2ea16e25cf52cb961b278501081bd6a376f1652"
}
```

### Sample 81: `649695cc337c50bf`

| Field | Value |
|---|---|
| SHA-256 | `649695cc337c50bf71bbf43b6c976d7937d6c504332db83e7d9e71213a0ac728` |
| Family label | `unknown` |
| File name | `WindowsSecurityUpdate.exe` |
| File type | `exe` |
| First seen | `2026-10-06 19:04:06` |
| Reporter | `smica83` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b9957f3d0d8de82d8d64b5c8ae437e2` |
| SHA-1 | `a83aeabe86879e155d507102e1b71c554f39cfbe` |
| SHA-256 | `649695cc337c50bf71bbf43b6c976d7937d6c504332db83e7d9e71213a0ac728` |
| SHA3-384 | `6e01501a40d91c15109324f365b169c9420f1c7142f7314fd56e191f4f139ec85b8eabbcac6c6f395975202e811260a8` |
| IMPHASH | `a07d43f4f1f9e66f3ef4ab55e02b7693` |
| TLSH | `T188C5191BE2A344ECC12FD17486639772FA70B85941347E6E1A98DB312F20E605B6EF35` |
| SSDEEP | `49152:ScWTgrD4vGfPqeDQ6zcWTgrD4vGfPqeDQ6:ATgbvvTgbv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_649695cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649695cc337c50bf71bbf43b6c976d7937d6c504332db83e7d9e71213a0ac728"
    family = "unknown"
    file_name = "WindowsSecurityUpdate.exe"
    file_type = "exe"
    first_seen = "2026-10-06 19:04:06"
  condition:
    hash.sha256(0, filesize) == "649695cc337c50bf71bbf43b6c976d7937d6c504332db83e7d9e71213a0ac728"
}
```

### Sample 82: `97a7cb9173bcef71`

| Field | Value |
|---|---|
| SHA-256 | `97a7cb9173bcef716a999ff6968805d416c02ccfa29a5f4f6fcc31e9a9878fba` |
| Family label | `unknown` |
| File name | `macho_97a7cb9173bc.bin` |
| File type | `macho` |
| First seen | `2026-10-06 19:00:41` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a229a2a56784b769c882a0b78187bbc7` |
| SHA-1 | `5b33c89b9c63fd91a35edb58906d38aab97b3e5f` |
| SHA-256 | `97a7cb9173bcef716a999ff6968805d416c02ccfa29a5f4f6fcc31e9a9878fba` |
| SHA3-384 | `c41597a02ab9e4569fe096ddc0ee6248f3d382a545463d9692b8e72b6f5d52a2078aaac9295181f3949141a77257edb1` |
| TLSH | `T15755F1018F72A0D6F5CCDB30362A8AAB9E617230844E11EB5B922E559D353D3F45B36F` |
| SSDEEP | `24576:vfhnGbjwruYm7N0qudA3FCPlxYZhhbdwBjuMsjN86ud83FC7zZWvHNbA:x2j15yxsrdT1RyZqpA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_97a7cb91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a7cb9173bcef716a999ff6968805d416c02ccfa29a5f4f6fcc31e9a9878fba"
    family = "unknown"
    file_name = "macho_97a7cb9173bc.bin"
    file_type = "macho"
    first_seen = "2026-10-06 19:00:41"
  condition:
    hash.sha256(0, filesize) == "97a7cb9173bcef716a999ff6968805d416c02ccfa29a5f4f6fcc31e9a9878fba"
}
```

### Sample 83: `c10b05f1e4780e30`

| Field | Value |
|---|---|
| SHA-256 | `c10b05f1e4780e30f31f78777b682093c7e3733d31a3cca229ba684865faa621` |
| Family label | `unknown` |
| File name | `Vlmc.exe` |
| File type | `exe` |
| First seen | `2026-10-06 18:39:01` |
| Reporter | `smica83` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f7d5f849dafab6a376f668b8f287fa3` |
| SHA-1 | `d8748709a0a6a4062938073393cea4b6a723adc3` |
| SHA-256 | `c10b05f1e4780e30f31f78777b682093c7e3733d31a3cca229ba684865faa621` |
| SHA3-384 | `40fb300de9dbbd6a7a2f8c31a3439065b96e7b9b66bbb7840787f1794595a96fd029b969530a8ac554540bf28cc5fd5c` |
| IMPHASH | `965e162fe6366ee377aa9bc80bdd5c65` |
| TLSH | `T1C34633945B4205D6ECFB423A94628284E6B2B4AB1330E5EF4B6173376F137F4683D762` |
| SSDEEP | `98304:F0l40xoCdizDBElf9E6Z+b4AMtd9dxfE1z1eaie9jKtsRpr:F0mSZdmD2F95Z+sJd9/sbeqBr` |
| ICON-DHASH | `b2b27069e8f0beba` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_c10b05f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c10b05f1e4780e30f31f78777b682093c7e3733d31a3cca229ba684865faa621"
    family = "unknown"
    file_name = "Vlmc.exe"
    file_type = "exe"
    first_seen = "2026-10-06 18:39:01"
  condition:
    hash.sha256(0, filesize) == "c10b05f1e4780e30f31f78777b682093c7e3733d31a3cca229ba684865faa621"
}
```

### Sample 84: `1b6ad824dde015ae`

| Field | Value |
|---|---|
| SHA-256 | `1b6ad824dde015ae8a70edc40ab20d85148c4377a8b8b0315b80749c3fe799d2` |
| Family label | `Mirai` |
| File name | `vcimanagement.m68k` |
| File type | `elf` |
| First seen | `2026-10-06 18:35:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baa1855507184d2891e3e00eab97907f` |
| SHA-1 | `994a96a36a3d082766dfad45520d44057fd9636b` |
| SHA-256 | `1b6ad824dde015ae8a70edc40ab20d85148c4377a8b8b0315b80749c3fe799d2` |
| SHA3-384 | `e95551f8f13ecfcc58225a47ffa51a085db9c41a1b0b075f306b4a38de75795ef1c3775e1e1c2564626716eaa1ff2eb7` |
| TLSH | `T117143A83F901DEBEF84BE3BA44934905B530FB6668630632B153BDAB9D3E1C41526F85` |
| SSDEEP | `3072:hm1sTg7Bp6KWA0HON+1SbTevqJ3eOlN1mcenalNVHjbifLn2Ps+yoKkH/:Anp6KWKyvqJOOc7alcLngyovf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_1b6ad824
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b6ad824dde015ae8a70edc40ab20d85148c4377a8b8b0315b80749c3fe799d2"
    family = "Mirai"
    file_name = "vcimanagement.m68k"
    file_type = "elf"
    first_seen = "2026-10-06 18:35:53"
  condition:
    hash.sha256(0, filesize) == "1b6ad824dde015ae8a70edc40ab20d85148c4377a8b8b0315b80749c3fe799d2"
}
```

### Sample 85: `42b9903e577d1744`

| Field | Value |
|---|---|
| SHA-256 | `42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251` |
| Family label | `unknown` |
| File name | `42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251.sh` |
| File type | `sh` |
| First seen | `2026-10-06 18:20:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c39b90eec4c28c25cbda26a9a75f1baa` |
| SHA-1 | `a40a17c8b26c25b965793ccd4e7db24ccd38b72b` |
| SHA-256 | `42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251` |
| SHA3-384 | `0e4474b98317d0853e8779fcda3c40730a287f4641b86dec6bd12713b73f56aeb8dd660426ea012d78dc350cd447e692` |
| TLSH | `T1C5829F3621F08B335A9065C4B3772BA54F769607456720A8B4FE1E359F5AB03B0FBB21` |
| SSDEEP | `192:cCul4hvZ5m5FG4j4HKNphv4iKLMW6MN7molZi:a4hvZ5m5FGGoKNphv4iKLMW6MN7mom` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_42b9903e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251"
    family = "unknown"
    file_name = "42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251.sh"
    file_type = "sh"
    first_seen = "2026-10-06 18:20:49"
  condition:
    hash.sha256(0, filesize) == "42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251"
}
```

### Sample 86: `d5b96f051559b216`

| Field | Value |
|---|---|
| SHA-256 | `d5b96f051559b216d0fdc3571e606105ceab4790e9e29bfd4ffd75b89a0af69b` |
| Family label | `unknown` |
| File name | `rooming.hta` |
| File type | `hta` |
| First seen | `2026-10-06 18:11:29` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e07ff00b1b65fd05c398fa5f63f3004` |
| SHA-1 | `d4fad7ce0e2babd690a5c16ea9bc00e2b9bbb866` |
| SHA-256 | `d5b96f051559b216d0fdc3571e606105ceab4790e9e29bfd4ffd75b89a0af69b` |
| SHA3-384 | `5b43b66a1da922039bc2a57250544f5316cf9cfa73a8d4c23740f5603a83329fcefa789713d20cec1cf20825938f074a` |
| TLSH | `T16D42195CAED062B0EA1707DE73AF24691228A0C7240DC484F94CDDE87F06BDC4A57B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzXbqFtC1S1WRUM:sXX+/DV7k/3OFthWRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_d5b96f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b96f051559b216d0fdc3571e606105ceab4790e9e29bfd4ffd75b89a0af69b"
    family = "unknown"
    file_name = "rooming.hta"
    file_type = "hta"
    first_seen = "2026-10-06 18:11:29"
  condition:
    hash.sha256(0, filesize) == "d5b96f051559b216d0fdc3571e606105ceab4790e9e29bfd4ffd75b89a0af69b"
}
```

### Sample 87: `07f9ea17427378ed`

| Field | Value |
|---|---|
| SHA-256 | `07f9ea17427378edcff042f019680f4149b0c34a1b589b8621a30e2c8e240310` |
| Family label | `unknown` |
| File name | `fuck_niggers_2.hta` |
| File type | `hta` |
| First seen | `2026-10-06 18:06:18` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95f3b272e868ae13c01e4b69980fb99f` |
| SHA-1 | `3f4ce9eb61100f874b5a2b8e7f61ab0fe518b8a0` |
| SHA-256 | `07f9ea17427378edcff042f019680f4149b0c34a1b589b8621a30e2c8e240310` |
| SHA3-384 | `b4f85ee5457ccc2ab5a00c1fd62b750c29cebddce60b5c2f8409e8c0a817244c8bddd4134c19cc4d3138614ab1268841` |
| TLSH | `T14542195CEED1A1B0EA1703DEB7AF28690228A0C7240DC484F54CDEE87F46BDD4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzPbqFtCnSqTwRUM:sXX+/DV7k/3mFtkTwRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_07f9ea17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f9ea17427378edcff042f019680f4149b0c34a1b589b8621a30e2c8e240310"
    family = "unknown"
    file_name = "fuck_niggers_2.hta"
    file_type = "hta"
    first_seen = "2026-10-06 18:06:18"
  condition:
    hash.sha256(0, filesize) == "07f9ea17427378edcff042f019680f4149b0c34a1b589b8621a30e2c8e240310"
}
```

### Sample 88: `265fb1b0dc44cfa0`

| Field | Value |
|---|---|
| SHA-256 | `265fb1b0dc44cfa05b94d2802189cf7aeb2a42905646f28453cf1e16941789dc` |
| Family label | `unknown` |
| File name | `MO_TA_VIEC_LAM_P5.zip` |
| File type | `zip` |
| First seen | `2026-10-06 17:46:18` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d9a74f8ac9971b09e954f63de3fbaa1` |
| SHA-1 | `df71bcb75d813edf075f39a4ca23855b22126265` |
| SHA-256 | `265fb1b0dc44cfa05b94d2802189cf7aeb2a42905646f28453cf1e16941789dc` |
| SHA3-384 | `9034d25592a0c68490f4086a8abc2c01085e1829031ee8d3f36121cac64626384ee1bb883f97425de7ebdc27eeedc956` |
| TLSH | `T12176338359CBC11950B0B034A132262FF3C3A6CA739B895FFB74857A27594375A239F9` |
| SSDEEP | `196608:iwV2AW2krnJW7fDIe1rbZTWXJ1QB28j+fpUpwuihcL4a3:72AW2+4XVXWXJ1Q9KfOp1KRa3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_265fb1b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "265fb1b0dc44cfa05b94d2802189cf7aeb2a42905646f28453cf1e16941789dc"
    family = "unknown"
    file_name = "MO_TA_VIEC_LAM_P5.zip"
    file_type = "zip"
    first_seen = "2026-10-06 17:46:18"
  condition:
    hash.sha256(0, filesize) == "265fb1b0dc44cfa05b94d2802189cf7aeb2a42905646f28453cf1e16941789dc"
}
```

### Sample 89: `4837b7a6c207af2d`

| Field | Value |
|---|---|
| SHA-256 | `4837b7a6c207af2dc9e3ef2b905cbc0d977efa3a4f31a85ca8ad5339704aae87` |
| Family label | `unknown` |
| File name | `zoom-update.msc` |
| File type | `msc` |
| First seen | `2026-10-06 17:37:31` |
| Reporter | `smica83` |
| Tags | `msc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4096e3abad13304a329de31e109424f9` |
| SHA-1 | `03b0ff7d4ccb7a6deeca2d707fc909b753b49fd3` |
| SHA-256 | `4837b7a6c207af2dc9e3ef2b905cbc0d977efa3a4f31a85ca8ad5339704aae87` |
| SHA3-384 | `15b19f59a1c9e123fc6ec3b52065a74ce6cb610d17231d8a6e7838743ad4125a59e254e2b6bbdd769a104569e77d50a3` |
| TLSH | `T1B6F58E315D262DB1A784110A68ED9BDECEE5434F25155CEFF707EB08E98FA06804B1EB` |
| SSDEEP | `24576:uS0XqfapEVUqXCvdJnic3weAnWKUPqXWS5GTn13jz0J7t9ovS+jnAoS8jj/ynRsn:uEmB0UXgbtM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msc`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_4837b7a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4837b7a6c207af2dc9e3ef2b905cbc0d977efa3a4f31a85ca8ad5339704aae87"
    family = "unknown"
    file_name = "zoom-update.msc"
    file_type = "msc"
    first_seen = "2026-10-06 17:37:31"
  condition:
    hash.sha256(0, filesize) == "4837b7a6c207af2dc9e3ef2b905cbc0d977efa3a4f31a85ca8ad5339704aae87"
}
```

### Sample 90: `11d7da51a1d765e6`

| Field | Value |
|---|---|
| SHA-256 | `11d7da51a1d765e6f6946b27566876a5c42e4d157bdb2c9f45dc579c87417f31` |
| Family label | `RustyStealer` |
| File name | `Havene catalog.pdf.exe` |
| File type | `exe` |
| First seen | `2026-10-06 17:34:24` |
| Reporter | `smica83` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f9fc33ab36f20a0938eb86652e6eaa1` |
| SHA-1 | `afd7870efc21f64af53990bf2f2b4f172b23ade7` |
| SHA-256 | `11d7da51a1d765e6f6946b27566876a5c42e4d157bdb2c9f45dc579c87417f31` |
| SHA3-384 | `a1aae4c0ecbdabda27fffb6357703e7db0babdea42f3c6ea2e622b7e7bf84e96227efdc8519ab45b53a235d7f9abe8a2` |
| IMPHASH | `14b5211b474625586733f7a3ad9cc73d` |
| TLSH | `T1FEB69D43E6A6C0E8C52AC071C346E2B2FA727C494B2575FB06E46E273E21ED05B3DB55` |
| SSDEEP | `98304:Y64iYWmrjOprKCsPmGkF2l5c6EGq6hfOB3Dp65RzwvSAogph3u+ywM4iD+vbaI+W:lYiFc5chGqw2B3ARhDcAbwRiD+vbaIWS` |
| ICON-DHASH | `64c28292b2aa8ed4` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_090_11d7da51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d7da51a1d765e6f6946b27566876a5c42e4d157bdb2c9f45dc579c87417f31"
    family = "RustyStealer"
    file_name = "Havene catalog.pdf.exe"
    file_type = "exe"
    first_seen = "2026-10-06 17:34:24"
  condition:
    hash.sha256(0, filesize) == "11d7da51a1d765e6f6946b27566876a5c42e4d157bdb2c9f45dc579c87417f31"
}
```

### Sample 91: `b4e2a808f57fc407`

| Field | Value |
|---|---|
| SHA-256 | `b4e2a808f57fc407bc2c7b7d3c6c42ca0e358d23bc6c6d4b49865ba3abd2d237` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-06 17:31:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `507a2810525984cec33ff8a91449215c` |
| SHA-1 | `efcb4fbb0332ded86eead25360c0ca1f40e8fb2d` |
| SHA-256 | `b4e2a808f57fc407bc2c7b7d3c6c42ca0e358d23bc6c6d4b49865ba3abd2d237` |
| SHA3-384 | `547384cc30f575f20b359775a8d93696272a3add638b46bc34c096f6d78b8eca9e49cb81d138f493cd60f8017fc6f128` |
| TLSH | `T130C419B6FD41D991C5D42ABEFB5EC2C833030378C3EA71429D06872569DF69A0E3DA91` |
| SSDEEP | `12288:POLJgVOjod6dwm82UX0+w7kzRcvouBktpW6k0a0GpRV9vsYE:qsEsOYk0Es` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b4e2a808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4e2a808f57fc407bc2c7b7d3c6c42ca0e358d23bc6c6d4b49865ba3abd2d237"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-06 17:31:29"
  condition:
    hash.sha256(0, filesize) == "b4e2a808f57fc407bc2c7b7d3c6c42ca0e358d23bc6c6d4b49865ba3abd2d237"
}
```

### Sample 92: `b4991411975fbe9a`

| Field | Value |
|---|---|
| SHA-256 | `b4991411975fbe9a19516114f5ad0c3dd897d3f998cf741db4661a09ba624cc1` |
| Family label | `Mirai` |
| File name | `sarm64` |
| File type | `elf` |
| First seen | `2026-10-06 17:21:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87a1b6b06b2e1357e8b3b7d1ce2176a8` |
| SHA-1 | `dce60f65a05a25716335af97552ab5d0aac5ac66` |
| SHA-256 | `b4991411975fbe9a19516114f5ad0c3dd897d3f998cf741db4661a09ba624cc1` |
| SHA3-384 | `9d37c7999beac7334fdcbcdbf0ae5615310b99d1ed5cc59a92b414cf47d6d41aa7f6c983bf8b40602110a470bbce6d99` |
| TLSH | `T117F45C5DFD1E3C41E3DBF278DB4E83E1A22FB1A0D32391A23982135CD5C69A9CAB0555` |
| SSDEEP | `12288:KQzbvCIHRELHg30G1OjhVRGcPRNQLgJIQPAHuzptw5QotyIY:/fABSOjhTGEDQGIYzpm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_b4991411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4991411975fbe9a19516114f5ad0c3dd897d3f998cf741db4661a09ba624cc1"
    family = "Mirai"
    file_name = "sarm64"
    file_type = "elf"
    first_seen = "2026-10-06 17:21:23"
  condition:
    hash.sha256(0, filesize) == "b4991411975fbe9a19516114f5ad0c3dd897d3f998cf741db4661a09ba624cc1"
}
```

### Sample 93: `ba8ea35fb544e00b`

| Field | Value |
|---|---|
| SHA-256 | `ba8ea35fb544e00be375e3ff080e5ed10af088c27f7cf12ee283e5351d740f2e` |
| Family label | `Mirai` |
| File name | `sarm64` |
| File type | `elf` |
| First seen | `2026-10-06 17:21:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edcba899c42693eae54c3d596ae5fb48` |
| SHA-1 | `182f92d2fbb760e23dc35194b151153fdfe87ecf` |
| SHA-256 | `ba8ea35fb544e00be375e3ff080e5ed10af088c27f7cf12ee283e5351d740f2e` |
| SHA3-384 | `2d90c66d2f2793035d9a69e5d9456ab4e03262c23b543e494fbcfa3f0b469b60a1743304e41454a61e17054359970992` |
| TLSH | `T196442366BCE73B61B44174B4A42A940514C3D1CAB782B6675DEF7D30BAD8FB5A280343` |
| SSDEEP | `6144:CvcYXcGPfgFItwrDuXJcmGCPSA9lJmnBKBsyUUZI1Jd3w0b:CvBJvtSDqimrSsyKBsHIIH13` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_ba8ea35f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba8ea35fb544e00be375e3ff080e5ed10af088c27f7cf12ee283e5351d740f2e"
    family = "Mirai"
    file_name = "sarm64"
    file_type = "elf"
    first_seen = "2026-10-06 17:21:13"
  condition:
    hash.sha256(0, filesize) == "ba8ea35fb544e00be375e3ff080e5ed10af088c27f7cf12ee283e5351d740f2e"
}
```

### Sample 94: `d14e45479e964178`

| Field | Value |
|---|---|
| SHA-256 | `d14e45479e964178f165e330954120cf0e3c26714af9a4339ccd41aa017a4c83` |
| Family label | `unknown` |
| File name | `INQUIRY -2026-17085.js` |
| File type | `js` |
| First seen | `2026-10-06 17:14:29` |
| Reporter | `James_inthe_box` |
| Tags | `exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a611642fb4ac78d061de94ea64da8ad` |
| SHA-1 | `51d35c4d2e3c7e5673775b5cf5943947e69ec33c` |
| SHA-256 | `d14e45479e964178f165e330954120cf0e3c26714af9a4339ccd41aa017a4c83` |
| SHA3-384 | `e114bc2f8afaf3954fb6a6e50e13af49d4c3d6e37e6a5f4580cc95381752b5b0fa14dde62f383f70bf6555b8144a7310` |
| TLSH | `T1BCF49E31627C905D2967A45B733BB1237A1EFB2DD2063B4045FE43C671E60BA92374AB` |
| SSDEEP | `12288:qIqpz9qQxmyFxIs+aE0L3y73dpDDxBNDu1Hfg5c92gR2D3NUBpSmuKFkIdB9gFUJ:qIq59qQxmkxxZ3CbdpDdBA1/Ec92gR2k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_d14e4547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14e45479e964178f165e330954120cf0e3c26714af9a4339ccd41aa017a4c83"
    family = "unknown"
    file_name = "INQUIRY -2026-17085.js"
    file_type = "js"
    first_seen = "2026-10-06 17:14:29"
  condition:
    hash.sha256(0, filesize) == "d14e45479e964178f165e330954120cf0e3c26714af9a4339ccd41aa017a4c83"
}
```

### Sample 95: `197f763bcd619f96`

| Field | Value |
|---|---|
| SHA-256 | `197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0` |
| Family label | `unknown` |
| File name | `9a.bat` |
| File type | `bat` |
| First seen | `2026-10-06 17:01:37` |
| Reporter | `anckhalion` |
| Tags | `bat, Braodo, loader, malvertising, sora-ai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c59759d0f56635ca3b2d161ea375275` |
| SHA-1 | `6ac878340c8be5253332e504b94112b577144571` |
| SHA-256 | `197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0` |
| SHA3-384 | `5305e799fae2ea1adff9321fb45402e386187cdcd9b21c4fd949a18a992a02323671f892158d27e481b320fffcb2fec4` |
| TLSH | `T1D493C021811D1D3F77AE629B08A91D2A69D44DC300751FCCF99C6ACE734ED271BB928A` |
| SSDEEP | `1536:52ymtk89le0J4lx4/pJ9CJSzdmybWPMXtTGTHf7ntNjhx5PtKg41bX1bLvU:58z/+lx4JDzdCEtTujt5Hag41BbL8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_197f763b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0"
    family = "unknown"
    file_name = "9a.bat"
    file_type = "bat"
    first_seen = "2026-10-06 17:01:37"
  condition:
    hash.sha256(0, filesize) == "197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0"
}
```

### Sample 96: `bef45f3b51f4d42e`

| Field | Value |
|---|---|
| SHA-256 | `bef45f3b51f4d42e2f0d5c4b44946d11e002f2b589be2fdf3e5ed2d0aad68ef3` |
| Family label | `Mirai` |
| File name | `vcimanagement.ppc` |
| File type | `elf` |
| First seen | `2026-10-06 16:59:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3f842922609a0a6e30a1510ad42f8cd` |
| SHA-1 | `776f02922e0211bb4e9413c09e7803a825115cd2` |
| SHA-256 | `bef45f3b51f4d42e2f0d5c4b44946d11e002f2b589be2fdf3e5ed2d0aad68ef3` |
| SHA3-384 | `cceda24c7f9e281ba44d18b9dc1f388c6dc5453fa39f160a74b93d828885e76b9bc1fd8c00437b181831ea7ef93254cc` |
| TLSH | `T1DC043902B70C0E47D1532EF0377B0BE097ABED5225B5A280751FAEC882B5DB66446EDD` |
| SSDEEP | `1536:5yXuJ9Gs9zbeEhBVx67xXUQqlPSmJ8svxLx922k8nSqxnoNDZBvDb1XTb7+fhQ9y:5yXuJ9GsF5zlTPdxaZ5XVQhQ4Wc4VpT8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_bef45f3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bef45f3b51f4d42e2f0d5c4b44946d11e002f2b589be2fdf3e5ed2d0aad68ef3"
    family = "Mirai"
    file_name = "vcimanagement.ppc"
    file_type = "elf"
    first_seen = "2026-10-06 16:59:39"
  condition:
    hash.sha256(0, filesize) == "bef45f3b51f4d42e2f0d5c4b44946d11e002f2b589be2fdf3e5ed2d0aad68ef3"
}
```

### Sample 97: `90438e02b7f3d87b`

| Field | Value |
|---|---|
| SHA-256 | `90438e02b7f3d87ba0d832308efe5f20d895713d52f614fd98e7fc3eb643b3b9` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-10-06 16:59:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34b6ebd70604f675d8c70da0eb9e80d0` |
| SHA-1 | `b46d0faa7aab8552f8cbca517c032d6fffba5300` |
| SHA-256 | `90438e02b7f3d87ba0d832308efe5f20d895713d52f614fd98e7fc3eb643b3b9` |
| SHA3-384 | `45751fd5635c78e8b8a4a1788b6966e3bd4fee597b4a2dfff440be80c4f553f6c0440ad3147deb7fd708ed034e6b7520` |
| TLSH | `T1EE534AC5A643D8F9ED1605762137E3338737F1390029DA87C769E936ACA3940EA5739C` |
| TELFHASH | `t10b31c4f65ebe4dfcb7d46448c31b6ad3293ae137142035b400b6ad9433e6d4151b9c79` |
| SSDEEP | `1536:+dvZ+2sahNerPGx9VzK6zbxZGeGJc4YnGxat0LIEmZMJShsq9HmFmarAX7:yRrsaheux9VzKZzJFa6MEVJRiHZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_90438e02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90438e02b7f3d87ba0d832308efe5f20d895713d52f614fd98e7fc3eb643b3b9"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-10-06 16:59:37"
  condition:
    hash.sha256(0, filesize) == "90438e02b7f3d87ba0d832308efe5f20d895713d52f614fd98e7fc3eb643b3b9"
}
```

### Sample 98: `e85c05fb2f529fa7`

| Field | Value |
|---|---|
| SHA-256 | `e85c05fb2f529fa7d8c02cd8b28a58b375e61c288c568fe531b5bd21d48df4c5` |
| Family label | `Mirai` |
| File name | `sora.mpsl` |
| File type | `elf` |
| First seen | `2026-10-06 16:54:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66d54b562680a4a7471a79ae3c423116` |
| SHA-1 | `3f8c154416db3abc0ce8bb2ec3d42f4407e3891b` |
| SHA-256 | `e85c05fb2f529fa7d8c02cd8b28a58b375e61c288c568fe531b5bd21d48df4c5` |
| SHA3-384 | `7c36fa34dab7d6c4493545050b9f75c44c95eac4abe9bec9b9aa1fd61aade65637f21d998a464dfe1b585d587de0480d` |
| TLSH | `T1E193D706BF610FF7DC9BDC3705A92B05289C665A31A97B35BA30D818F64B21F19E3C64` |
| SSDEEP | `1536:NF2GXYZ8a8fnwEvLNPENIdhs9WZx0ZCufqNKK:NFjXYyCEx04KK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_e85c05fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e85c05fb2f529fa7d8c02cd8b28a58b375e61c288c568fe531b5bd21d48df4c5"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-10-06 16:54:21"
  condition:
    hash.sha256(0, filesize) == "e85c05fb2f529fa7d8c02cd8b28a58b375e61c288c568fe531b5bd21d48df4c5"
}
```

### Sample 99: `5e2453297f38a596`

| Field | Value |
|---|---|
| SHA-256 | `5e2453297f38a5965bd9cbb86eeebf81001044e842a65c7ff3fcdbeefc565a19` |
| Family label | `Mirai` |
| File name | `sora.mpsl` |
| File type | `elf` |
| First seen | `2026-10-06 16:54:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aafd2f2d7a18e32d5598c664ce5b5c47` |
| SHA-1 | `d080cabb159301b9e1eaa88a5025f6300d861b34` |
| SHA-256 | `5e2453297f38a5965bd9cbb86eeebf81001044e842a65c7ff3fcdbeefc565a19` |
| SHA3-384 | `506479e77e8992dc1eda14a0c7ba5058c4d2e504d1a0f24cd0bf42bd78c7d8a74de3abc2720f614e3a78d78254a9f036` |
| TLSH | `T11FD2D17EE5B481C5FD8E0C7E849C3FA24E59A581220BDB9563218C896732C5BF17F4B8` |
| SSDEEP | `384:e8pVWtmRsLYEpB6V8S628FuRUuNJG9whQ3Cfbo6w+K95orjItXwVJVuFRWGVCz0Y:jMYHb62x4ahQ3CfdwLjjtXw9gWj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_5e245329
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e2453297f38a5965bd9cbb86eeebf81001044e842a65c7ff3fcdbeefc565a19"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-10-06 16:54:06"
  condition:
    hash.sha256(0, filesize) == "5e2453297f38a5965bd9cbb86eeebf81001044e842a65c7ff3fcdbeefc565a19"
}
```

### Sample 100: `9f2ccb39fd57752c`

| Field | Value |
|---|---|
| SHA-256 | `9f2ccb39fd57752cdcee1b20489d08fcfd78167ebf43eda09e14eb17f32d81d2` |
| Family label | `Mirai` |
| File name | `sora.arm` |
| File type | `elf` |
| First seen | `2026-10-06 16:49:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df52c4bad4e1418424b7c1492402a8e3` |
| SHA-1 | `b35835f721275ffeb372e6cf3576fa4bfca4da2f` |
| SHA-256 | `9f2ccb39fd57752cdcee1b20489d08fcfd78167ebf43eda09e14eb17f32d81d2` |
| SHA3-384 | `3d4b22cc770c57d7ab1d967747db4b1d376f9cbaebb86fa43bed2a27492fbd5506a46d10f5d3e1a7bd209822ac151fa0` |
| TLSH | `T1E6630891B881A626C2D1537BFA6F008E372457D8E2DA33139D255FA0778AC1F0D57F8A` |
| TELFHASH | `t14a41d1f74ba40bcc67e8a149c98c711c5ff5b05aaf092483590caa4fc85b5d2b00e437` |
| SSDEEP | `1536:pOTAiIYaMBktkIwn8U0yaPSmuSt8M8fhWtu5v36L:pOTAiLaMH+uSerpeu5+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_9f2ccb39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f2ccb39fd57752cdcee1b20489d08fcfd78167ebf43eda09e14eb17f32d81d2"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-10-06 16:49:20"
  condition:
    hash.sha256(0, filesize) == "9f2ccb39fd57752cdcee1b20489d08fcfd78167ebf43eda09e14eb17f32d81d2"
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
 * Generated: 2026-10-07T06:09:30.236865+00:00
 */

rule MalwareBazaar_Mirai_001_2d439ae8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d439ae8d04b35e424c39632d77c9ceb096a1c0f935d07aea9fbfab18b67c151"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-10-07 06:04:11"
  condition:
    hash.sha256(0, filesize) == "2d439ae8d04b35e424c39632d77c9ceb096a1c0f935d07aea9fbfab18b67c151"
}

rule MalwareBazaar_unknown_002_a9a97675
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a97675dd4fd2cad9b66f31c0bb3cf177cfbe40f29a664abce74b11da645984"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 05:48:20"
  condition:
    hash.sha256(0, filesize) == "a9a97675dd4fd2cad9b66f31c0bb3cf177cfbe40f29a664abce74b11da645984"
}

rule MalwareBazaar_unknown_003_19faee0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19faee0d47e5ba75566c00afc5e6e64a29744ca6f366c32c0d22acd147773e00"
    family = "unknown"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-10-07 05:33:34"
  condition:
    hash.sha256(0, filesize) == "19faee0d47e5ba75566c00afc5e6e64a29744ca6f366c32c0d22acd147773e00"
}

rule MalwareBazaar_Mirai_004_618a1b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618a1b1d30d6f2bd4a2a122c6caa7cada264460175e4c41a9a7ab39d17b466b3"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-07 05:13:24"
  condition:
    hash.sha256(0, filesize) == "618a1b1d30d6f2bd4a2a122c6caa7cada264460175e4c41a9a7ab39d17b466b3"
}

rule MalwareBazaar_unknown_005_3740e388
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538"
    family = "unknown"
    file_name = "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538"
    file_type = "macho"
    first_seen = "2026-10-07 05:12:59"
  condition:
    hash.sha256(0, filesize) == "3740e3883b64840461b3dfe2ce86695f32a14f28c8e0353c860ff6939a8c2538"
}

rule MalwareBazaar_unknown_006_c4c7cc2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5"
    family = "unknown"
    file_name = "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5"
    file_type = "macho"
    first_seen = "2026-10-07 05:12:39"
  condition:
    hash.sha256(0, filesize) == "c4c7cc2f8e281b36d0bc29de6e08d354d83c4f734acaded25e7c8dfb1f580db5"
}

rule MalwareBazaar_Mirai_007_92e56ff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92e56ff0e46fb9e52f8866bbf4e5c1c1e989a13377aa6dcc9079a8adcdaa4bc9"
    family = "Mirai"
    file_name = "bash"
    file_type = "elf"
    first_seen = "2026-10-07 05:03:26"
  condition:
    hash.sha256(0, filesize) == "92e56ff0e46fb9e52f8866bbf4e5c1c1e989a13377aa6dcc9079a8adcdaa4bc9"
}

rule MalwareBazaar_unknown_008_040a0da5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040a0da5c3f26dc1b971271e13e8930c7680b8aeef8aba87f885009760a71709"
    family = "unknown"
    file_name = "beacon_x"
    file_type = "elf"
    first_seen = "2026-10-07 04:46:22"
  condition:
    hash.sha256(0, filesize) == "040a0da5c3f26dc1b971271e13e8930c7680b8aeef8aba87f885009760a71709"
}

rule MalwareBazaar_Mirai_009_a45e7396
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a45e7396cd5e64cf9ea7567f0e8d56d4a41c4b1b168981f8f0fb33e7e2a3dce5"
    family = "Mirai"
    file_name = "5r3fqt67ew531has4231.arm"
    file_type = "elf"
    first_seen = "2026-10-07 04:46:18"
  condition:
    hash.sha256(0, filesize) == "a45e7396cd5e64cf9ea7567f0e8d56d4a41c4b1b168981f8f0fb33e7e2a3dce5"
}

rule MalwareBazaar_Gafgyt_010_965e3c0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965e3c0a85daa83a38e5841a77fad2407f42b28870ccab3f48efb7999c424127"
    family = "Gafgyt"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-07 04:37:25"
  condition:
    hash.sha256(0, filesize) == "965e3c0a85daa83a38e5841a77fad2407f42b28870ccab3f48efb7999c424127"
}

rule MalwareBazaar_unknown_011_d292f68f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d292f68fcc94542edf5761239a77cd7d17f3ed5d7fc85451cefb8d2ad7bcb06b"
    family = "unknown"
    file_name = "python37.dll"
    file_type = "dll"
    first_seen = "2026-10-07 04:32:01"
  condition:
    hash.sha256(0, filesize) == "d292f68fcc94542edf5761239a77cd7d17f3ed5d7fc85451cefb8d2ad7bcb06b"
}

rule MalwareBazaar_unknown_012_fed1a155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fed1a1556b70e2d634b05a951a4c5f89617d80e1b1cde5c620f7cf7b2970fdd5"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.exe"
    file_type = "exe"
    first_seen = "2026-10-07 04:31:41"
  condition:
    hash.sha256(0, filesize) == "fed1a1556b70e2d634b05a951a4c5f89617d80e1b1cde5c620f7cf7b2970fdd5"
}

rule MalwareBazaar_Mirai_013_7bb04811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bb04811138fbe63e93a45e2e3afe0e68e0145e2dd06626880579922c191d611"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-10-07 04:24:27"
  condition:
    hash.sha256(0, filesize) == "7bb04811138fbe63e93a45e2e3afe0e68e0145e2dd06626880579922c191d611"
}

rule MalwareBazaar_unknown_014_91bb4e80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91bb4e80a57b2738a6725cc20160e8f43f4398b509c104e6c4fefaec1373c703"
    family = "unknown"
    file_name = "Xteam30.hta"
    file_type = "hta"
    first_seen = "2026-10-07 04:20:14"
  condition:
    hash.sha256(0, filesize) == "91bb4e80a57b2738a6725cc20160e8f43f4398b509c104e6c4fefaec1373c703"
}

rule MalwareBazaar_NetSupport_015_52b29b43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52b29b43b364314968aaca8ef61f87e05d68bca81e3dfd445093c18cd6ea5ceb"
    family = "NetSupport"
    file_name = "cognition.pbi"
    file_type = "zip"
    first_seen = "2026-10-07 04:14:54"
  condition:
    hash.sha256(0, filesize) == "52b29b43b364314968aaca8ef61f87e05d68bca81e3dfd445093c18cd6ea5ceb"
}

rule MalwareBazaar_NetSupport_016_c57fa43f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c57fa43fe729fc45ac725798a3f12d1eafcbe9b91c14046e98485033cb7e4fc9"
    family = "NetSupport"
    file_name = "A0-6A086A5-A4djfhhryy-45.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 04:14:06"
  condition:
    hash.sha256(0, filesize) == "c57fa43fe729fc45ac725798a3f12d1eafcbe9b91c14046e98485033cb7e4fc9"
}

rule MalwareBazaar_unknown_017_fef5a6ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fef5a6cee655024888d3a12b10e9cba3390e325315ef68405da9c8bf3e13a267"
    family = "unknown"
    file_name = "Fabrics.a3x"
    file_type = "a3x"
    first_seen = "2026-10-07 04:13:11"
  condition:
    hash.sha256(0, filesize) == "fef5a6cee655024888d3a12b10e9cba3390e325315ef68405da9c8bf3e13a267"
}

rule MalwareBazaar_unknown_018_f0712721
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0712721a0095d99f9ce6d4650115ddb63e303d8ecefaa9916861c0b331e21a0"
    family = "unknown"
    file_name = "d-56364130-1079Ef-f.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 04:11:43"
  condition:
    hash.sha256(0, filesize) == "f0712721a0095d99f9ce6d4650115ddb63e303d8ecefaa9916861c0b331e21a0"
}

rule MalwareBazaar_PureLogsStealer_019_ef17ba04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef17ba04b4f40ab80c46d923a4253b56236a94f2aa844b645662ae1cefefcf14"
    family = "PureLogsStealer"
    file_name = "RFQ_Acquire-GT_07Oct2026.js"
    file_type = "js"
    first_seen = "2026-10-07 04:04:09"
  condition:
    hash.sha256(0, filesize) == "ef17ba04b4f40ab80c46d923a4253b56236a94f2aa844b645662ae1cefefcf14"
}

rule MalwareBazaar_unknown_020_aa84a72e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa84a72e470b4a4b8c581e5867a13118fc43756b62796556de3dfe4a688c3ddb"
    family = "unknown"
    file_name = "e5d4a291-f991-47fc-85cf-dcccb773affc.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 03:54:13"
  condition:
    hash.sha256(0, filesize) == "aa84a72e470b4a4b8c581e5867a13118fc43756b62796556de3dfe4a688c3ddb"
}

rule MalwareBazaar_unknown_021_6ee94841
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee948412a06d2402d7967975e410a7069c75d0bcfb6afd0d7a9215579e2a5c3"
    family = "unknown"
    file_name = "8d156900-bcb7-11f1-997f-ea71e2325182.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 03:53:48"
  condition:
    hash.sha256(0, filesize) == "6ee948412a06d2402d7967975e410a7069c75d0bcfb6afd0d7a9215579e2a5c3"
}

rule MalwareBazaar_unknown_022_c184c0f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c184c0f22af4708fc50708003da89f2811530f98690ab37036951c2f998d55c6"
    family = "unknown"
    file_name = "Summary_Raw_v8.3.ps1"
    file_type = "ps1"
    first_seen = "2026-10-07 03:28:06"
  condition:
    hash.sha256(0, filesize) == "c184c0f22af4708fc50708003da89f2811530f98690ab37036951c2f998d55c6"
}

rule MalwareBazaar_unknown_023_135607f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135607f1e8aafbb7b49de471400f3d30399101096583f418bcbd18cca8e700be"
    family = "unknown"
    file_name = "ZateEngine.exe"
    file_type = "exe"
    first_seen = "2026-10-07 03:26:00"
  condition:
    hash.sha256(0, filesize) == "135607f1e8aafbb7b49de471400f3d30399101096583f418bcbd18cca8e700be"
}

rule MalwareBazaar_unknown_024_2e65411b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e65411b686c155415d7644f88ba91cb67c715e5b1a7094962732749358142cc"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-10-07 03:09:13"
  condition:
    hash.sha256(0, filesize) == "2e65411b686c155415d7644f88ba91cb67c715e5b1a7094962732749358142cc"
}

rule MalwareBazaar_unknown_025_8c652391
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c65239167f3ec609a5a992ed143b68b3c1b3a5985cf8a6d3f528081de15d0ee"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 03:07:58"
  condition:
    hash.sha256(0, filesize) == "8c65239167f3ec609a5a992ed143b68b3c1b3a5985cf8a6d3f528081de15d0ee"
}

rule MalwareBazaar_unknown_026_d0fae14a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0fae14af3bda82a509889852346f4797e6232e03a29f2f7142e574f6aca127e"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-10-07 03:05:20"
  condition:
    hash.sha256(0, filesize) == "d0fae14af3bda82a509889852346f4797e6232e03a29f2f7142e574f6aca127e"
}

rule MalwareBazaar_unknown_027_dc978cec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc978cecad6e55b168f42ffcaab296a4513c3a46af58707fb1f6af5d162a69e0"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 03:01:40"
  condition:
    hash.sha256(0, filesize) == "dc978cecad6e55b168f42ffcaab296a4513c3a46af58707fb1f6af5d162a69e0"
}

rule MalwareBazaar_unknown_028_74900937
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749009376b352dfd21f7289f549c0ed3ff515f813eb1eaf2e604ba75be02c9c2"
    family = "unknown"
    file_name = "Installer21691x64.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:59:57"
  condition:
    hash.sha256(0, filesize) == "749009376b352dfd21f7289f549c0ed3ff515f813eb1eaf2e604ba75be02c9c2"
}

rule MalwareBazaar_unknown_029_29ab58d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ab58d7ef08f98ba4cb0e20b0989eb8460c6247283c530d41bc9dcf67a9e711"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-10-07 02:59:26"
  condition:
    hash.sha256(0, filesize) == "29ab58d7ef08f98ba4cb0e20b0989eb8460c6247283c530d41bc9dcf67a9e711"
}

rule MalwareBazaar_unknown_030_2c195b62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c195b625dee9271f543a9be087c9fb1b641255be29cc7c88fd811f7e1fe71d5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:58:49"
  condition:
    hash.sha256(0, filesize) == "2c195b625dee9271f543a9be087c9fb1b641255be29cc7c88fd811f7e1fe71d5"
}

rule MalwareBazaar_unknown_031_2dbc1c39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dbc1c3920315f24899eb0f9574d0c5e2e0c5b42d280b6a7a506b176305f7b09"
    family = "unknown"
    file_name = "Setup_latest.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:56:43"
  condition:
    hash.sha256(0, filesize) == "2dbc1c3920315f24899eb0f9574d0c5e2e0c5b42d280b6a7a506b176305f7b09"
}

rule MalwareBazaar_unknown_032_27c743d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27c743d1ff6531bcd8fb09f0a91caea95ad72c34e83782660236b6b34b81cde5"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:55:34"
  condition:
    hash.sha256(0, filesize) == "27c743d1ff6531bcd8fb09f0a91caea95ad72c34e83782660236b6b34b81cde5"
}

rule MalwareBazaar_unknown_033_dba820c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba820c1f2c4778166063b0a20563b51c160ee6a3b08e4d5c2d4d7153a3ec081"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full_patched.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:54:33"
  condition:
    hash.sha256(0, filesize) == "dba820c1f2c4778166063b0a20563b51c160ee6a3b08e4d5c2d4d7153a3ec081"
}

rule MalwareBazaar_unknown_034_01a6d7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01a6d7a943d1287a48936923b86b46b6a5e094ac5cb8803510a2f408d36e6239"
    family = "unknown"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-07 02:54:25"
  condition:
    hash.sha256(0, filesize) == "01a6d7a943d1287a48936923b86b46b6a5e094ac5cb8803510a2f408d36e6239"
}

rule MalwareBazaar_unknown_035_a0df6a94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0df6a94057dfad6ec1b8985845d9517ff7c5ac7257fa7eedc0b8a058f7154e4"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-10-07 02:53:39"
  condition:
    hash.sha256(0, filesize) == "a0df6a94057dfad6ec1b8985845d9517ff7c5ac7257fa7eedc0b8a058f7154e4"
}

rule MalwareBazaar_unknown_036_b17689e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b17689e3da2c11a8034dee9389c5577366a3b4cbdfc77419c997713d5082dfc5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:52:41"
  condition:
    hash.sha256(0, filesize) == "b17689e3da2c11a8034dee9389c5577366a3b4cbdfc77419c997713d5082dfc5"
}

rule MalwareBazaar_unknown_037_d16d828d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d16d828d6538f903ab4b487994ced8f19a7cffc23944d30b7b724a194628b443"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-10-07 02:52:09"
  condition:
    hash.sha256(0, filesize) == "d16d828d6538f903ab4b487994ced8f19a7cffc23944d30b7b724a194628b443"
}

rule MalwareBazaar_unknown_038_372f8a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372f8a434264575c7adeaf66ffc090b454fab89a1ac5f49986f2a9ed8d25d357"
    family = "unknown"
    file_name = "𝗦𝗘𝗧𝗨𝗣.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:51:56"
  condition:
    hash.sha256(0, filesize) == "372f8a434264575c7adeaf66ffc090b454fab89a1ac5f49986f2a9ed8d25d357"
}

rule MalwareBazaar_Formbook_039_b85d4673
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b85d4673ac19ee208e96eff1e860d4b110a1eac0620464193bde12a85fb54115"
    family = "Formbook"
    file_name = "PO.2610041 Dan PO.2610042.pdf.js"
    file_type = "js"
    first_seen = "2026-10-07 02:49:34"
  condition:
    hash.sha256(0, filesize) == "b85d4673ac19ee208e96eff1e860d4b110a1eac0620464193bde12a85fb54115"
}

rule MalwareBazaar_unknown_040_eff4b583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff4b583d6a3e0743b7ad853a8227cc04b83eb4d855cac31bdef4fb0185326a9"
    family = "unknown"
    file_name = "𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-10-07 02:48:16"
  condition:
    hash.sha256(0, filesize) == "eff4b583d6a3e0743b7ad853a8227cc04b83eb4d855cac31bdef4fb0185326a9"
}

rule MalwareBazaar_unknown_041_187089df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a"
    family = "unknown"
    file_name = "187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:58:57"
  condition:
    hash.sha256(0, filesize) == "187089dffb448a9fc3d858e1d539ea70ba06a706d2b63dd44afc89d2ef1d2f8a"
}

rule MalwareBazaar_unknown_042_a36fbc11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a"
    family = "unknown"
    file_name = "a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:57:29"
  condition:
    hash.sha256(0, filesize) == "a36fbc117b0582e076f28cb9c81680c61f45a2ab9eac0f99ddb75a59537aab7a"
}

rule MalwareBazaar_unknown_043_7ffa8cea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9"
    family = "unknown"
    file_name = "7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:57:09"
  condition:
    hash.sha256(0, filesize) == "7ffa8ceaba695ecb58868eac30c83433b87854f8ef6ba6d97938bbd462d486a9"
}

rule MalwareBazaar_Mirai_044_8b3b5fca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b3b5fcac17c2be4accd5c596d8b51184f39e6cf65ebcac939d02041cedf502e"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-07 01:56:23"
  condition:
    hash.sha256(0, filesize) == "8b3b5fcac17c2be4accd5c596d8b51184f39e6cf65ebcac939d02041cedf502e"
}

rule MalwareBazaar_unknown_045_77a8d1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a8d1bcbc9c79e76e64b5fd50aeda23d4d9a0ca42299f0f7a72f8da032fcc54"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-10-07 01:52:13"
  condition:
    hash.sha256(0, filesize) == "77a8d1bcbc9c79e76e64b5fd50aeda23d4d9a0ca42299f0f7a72f8da032fcc54"
}

rule MalwareBazaar_unknown_046_b106a8b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76"
    family = "unknown"
    file_name = "b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:50:28"
  condition:
    hash.sha256(0, filesize) == "b106a8b8ffa1c67e0e8f21a2015d0f0935e16e9e710c95b1bef3f924d532bd76"
}

rule MalwareBazaar_unknown_047_24abb470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160"
    family = "unknown"
    file_name = "24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160.exe"
    file_type = "exe"
    first_seen = "2026-10-07 01:49:55"
  condition:
    hash.sha256(0, filesize) == "24abb4702809d350ec17986d645a0d453efc0fd6d499d87fb01e0b5cb1a65160"
}

rule MalwareBazaar_unknown_048_ffce7a38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffce7a3896c7e9e8172737d45c1eaed7f62b0a09b65ce22c5eeff9f25b7ace9d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 01:39:14"
  condition:
    hash.sha256(0, filesize) == "ffce7a3896c7e9e8172737d45c1eaed7f62b0a09b65ce22c5eeff9f25b7ace9d"
}

rule MalwareBazaar_unknown_049_0730cfb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0730cfb40dfc49e8b00344d72312c96832330b214c011d40fa338f3da2c84124"
    family = "unknown"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-07 01:10:30"
  condition:
    hash.sha256(0, filesize) == "0730cfb40dfc49e8b00344d72312c96832330b214c011d40fa338f3da2c84124"
}

rule MalwareBazaar_Mirai_050_cff2863f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cff2863f1c2f4c0800f43bf600f2107cee2b3e5df7591f58462190a8aa3993f9"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-07 01:02:20"
  condition:
    hash.sha256(0, filesize) == "cff2863f1c2f4c0800f43bf600f2107cee2b3e5df7591f58462190a8aa3993f9"
}

rule MalwareBazaar_Mirai_051_2c75acfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c75acfa406e571ba0898b6e648209afd620caa782a73f8150fbc0412c099bc8"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-07 00:57:47"
  condition:
    hash.sha256(0, filesize) == "2c75acfa406e571ba0898b6e648209afd620caa782a73f8150fbc0412c099bc8"
}

rule MalwareBazaar_Mirai_052_64b9e5ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64b9e5ee8f6e01bc1c7fff904ceaa5592d01b037afcf7b7007d2e2b00a81143c"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-07 00:50:26"
  condition:
    hash.sha256(0, filesize) == "64b9e5ee8f6e01bc1c7fff904ceaa5592d01b037afcf7b7007d2e2b00a81143c"
}

rule MalwareBazaar_Mirai_053_dfc2b462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfc2b462b12a6f87dd8880222a8eff713317ace50b7f393923b3b44f7c2a26ea"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-10-07 00:49:26"
  condition:
    hash.sha256(0, filesize) == "dfc2b462b12a6f87dd8880222a8eff713317ace50b7f393923b3b44f7c2a26ea"
}

rule MalwareBazaar_Mirai_054_260645ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "260645ee1178499fe369898f91ed54969e1c83358e343f9e64bc88aae58ff1cb"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-10-07 00:37:16"
  condition:
    hash.sha256(0, filesize) == "260645ee1178499fe369898f91ed54969e1c83358e343f9e64bc88aae58ff1cb"
}

rule MalwareBazaar_unknown_055_cc85c7ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc85c7eff50e4df105b28b300fae9603ad3d1653408c6bdc5a2665a16c379103"
    family = "unknown"
    file_name = "macho_cc85c7eff50e.bin"
    file_type = "macho"
    first_seen = "2026-10-07 00:14:00"
  condition:
    hash.sha256(0, filesize) == "cc85c7eff50e4df105b28b300fae9603ad3d1653408c6bdc5a2665a16c379103"
}

rule MalwareBazaar_Mirai_056_cb1c3496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb1c3496202d7eb1803dc24fbecc332a245b52878084c1af23c2cca3ea52de09"
    family = "Mirai"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-10-07 00:09:00"
  condition:
    hash.sha256(0, filesize) == "cb1c3496202d7eb1803dc24fbecc332a245b52878084c1af23c2cca3ea52de09"
}

rule MalwareBazaar_unknown_057_1ebbe147
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ebbe1479d2be9b5ddae584a2d987e5f6f4ce14c1f002bb8bd1fb7e13046969e"
    family = "unknown"
    file_name = "macho_1ebbe1479d2b.bin"
    file_type = "macho"
    first_seen = "2026-10-07 00:04:24"
  condition:
    hash.sha256(0, filesize) == "1ebbe1479d2be9b5ddae584a2d987e5f6f4ce14c1f002bb8bd1fb7e13046969e"
}

rule MalwareBazaar_Mirai_058_be2c2884
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be2c28842c350d43d2b3ca8822221164e190d0594be464ef80bff87c8f352207"
    family = "Mirai"
    file_name = "ntp"
    file_type = "elf"
    first_seen = "2026-10-06 23:53:15"
  condition:
    hash.sha256(0, filesize) == "be2c28842c350d43d2b3ca8822221164e190d0594be464ef80bff87c8f352207"
}

rule MalwareBazaar_Mirai_059_74f3d4e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7"
    family = "Mirai"
    file_name = "74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7"
    file_type = "elf"
    first_seen = "2026-10-06 23:32:17"
  condition:
    hash.sha256(0, filesize) == "74f3d4e41fcb7a41eb5a9e6a768d25f647073d750e6d2af600a4e9e3c9de10e7"
}

rule MalwareBazaar_Mirai_060_18cf4d15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f"
    family = "Mirai"
    file_name = "18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f"
    file_type = "elf"
    first_seen = "2026-10-06 23:23:27"
  condition:
    hash.sha256(0, filesize) == "18cf4d150e2e3826951ef827095803a3ccef4e15c552e8f96340a025f73c501f"
}

rule MalwareBazaar_Mirai_061_c027df0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041"
    family = "Mirai"
    file_name = "c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041"
    file_type = "elf"
    first_seen = "2026-10-06 23:03:00"
  condition:
    hash.sha256(0, filesize) == "c027df0ed143719add201430d47033f8cb33bfeb74f830c73f5fb01c4932a041"
}

rule MalwareBazaar_Mirai_062_cbcefa22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642"
    family = "Mirai"
    file_name = "cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642"
    file_type = "elf"
    first_seen = "2026-10-06 22:32:47"
  condition:
    hash.sha256(0, filesize) == "cbcefa22c0ff043ff55e4e4ad1bea200b32d8fe420fe6d9c0d7a4f4dfcec1642"
}

rule MalwareBazaar_Mirai_063_fa2384bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa2384bd1fe35beb69afa1289e4856b015a9f822c4c8fc5acfdafa82b47aa94c"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-10-06 22:32:42"
  condition:
    hash.sha256(0, filesize) == "fa2384bd1fe35beb69afa1289e4856b015a9f822c4c8fc5acfdafa82b47aa94c"
}

rule MalwareBazaar_Gafgyt_064_20d4672f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20d4672f40c452d53b41227f669c481703677e302954c52158515f7003d2fb27"
    family = "Gafgyt"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-10-06 22:32:40"
  condition:
    hash.sha256(0, filesize) == "20d4672f40c452d53b41227f669c481703677e302954c52158515f7003d2fb27"
}

rule MalwareBazaar_unknown_065_cd3158bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd3158bdde5b7145a69e72579fb14577c0f8eb1e49de549968a8ecbf6c3c4701"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-06 22:32:23"
  condition:
    hash.sha256(0, filesize) == "cd3158bdde5b7145a69e72579fb14577c0f8eb1e49de549968a8ecbf6c3c4701"
}

rule MalwareBazaar_Mirai_066_243d7d7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c"
    family = "Mirai"
    file_name = "243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c"
    file_type = "sh"
    first_seen = "2026-10-06 22:08:38"
  condition:
    hash.sha256(0, filesize) == "243d7d7c79cccb577e5bc2eade7f2b6d32c502cbd39635f80476610035ae080c"
}

rule MalwareBazaar_Mirai_067_e74072e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e74072e835179517a8591dab94f3e9375289318fe680840e61503b9c04336666"
    family = "Mirai"
    file_name = "ntpd"
    file_type = "elf"
    first_seen = "2026-10-06 21:56:32"
  condition:
    hash.sha256(0, filesize) == "e74072e835179517a8591dab94f3e9375289318fe680840e61503b9c04336666"
}

rule MalwareBazaar_WannaCry_068_5ec4c1ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704"
    family = "WannaCry"
    file_name = "5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704"
    file_type = "exe"
    first_seen = "2026-10-06 21:15:41"
  condition:
    hash.sha256(0, filesize) == "5ec4c1ecaf67ba48a7f6ccebc065e587e7629654e455b15f67894240e63ac704"
}

rule MalwareBazaar_Gafgyt_069_0fad00dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fad00ddec16b67f3131aa4efffbe32d78fca178407895920b7549667d7bbfbf"
    family = "Gafgyt"
    file_name = "handshakebins.sh"
    file_type = "sh"
    first_seen = "2026-10-06 21:09:05"
  condition:
    hash.sha256(0, filesize) == "0fad00ddec16b67f3131aa4efffbe32d78fca178407895920b7549667d7bbfbf"
}

rule MalwareBazaar_Mirai_070_64b9c600
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64b9c6000e30cd09d2f81b418df20e1ff916fc0e34100df262830c8d15ba4cd8"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-06 20:55:29"
  condition:
    hash.sha256(0, filesize) == "64b9c6000e30cd09d2f81b418df20e1ff916fc0e34100df262830c8d15ba4cd8"
}

rule MalwareBazaar_Gafgyt_071_daeb4ddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daeb4dddaefa21f1e952b3a3e606f91d7c95955db3458730d30a0a218d005246"
    family = "Gafgyt"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-10-06 20:40:37"
  condition:
    hash.sha256(0, filesize) == "daeb4dddaefa21f1e952b3a3e606f91d7c95955db3458730d30a0a218d005246"
}

rule MalwareBazaar_Mirai_072_b98a0909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98a0909267bca4d6296b544d4463e00f28f38099dd4504df1c6cdeac15a760f"
    family = "Mirai"
    file_name = "kernal"
    file_type = "elf"
    first_seen = "2026-10-06 20:35:53"
  condition:
    hash.sha256(0, filesize) == "b98a0909267bca4d6296b544d4463e00f28f38099dd4504df1c6cdeac15a760f"
}

rule MalwareBazaar_unknown_073_0cd4604d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cd4604de3284d716488b41fe24760b3375f116651d1e7a325736de8950c196e"
    family = "unknown"
    file_name = "Текст Договора - версия 3.lnk"
    file_type = "lnk"
    first_seen = "2026-10-06 20:25:56"
  condition:
    hash.sha256(0, filesize) == "0cd4604de3284d716488b41fe24760b3375f116651d1e7a325736de8950c196e"
}

rule MalwareBazaar_AgentTesla_074_5209aa62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5209aa6242215875f7f9bccfca412a72d0fd99db10e87ee7eab113cf88628d0c"
    family = "AgentTesla"
    file_name = "SKM_7209435700.js"
    file_type = "js"
    first_seen = "2026-10-06 20:21:49"
  condition:
    hash.sha256(0, filesize) == "5209aa6242215875f7f9bccfca412a72d0fd99db10e87ee7eab113cf88628d0c"
}

rule MalwareBazaar_Mirai_075_3feed21d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3feed21d01cd1f34f6c9dec6e7115a94865e4e2dc76002c6ef2384e461993081"
    family = "Mirai"
    file_name = "vcimanagement.mips"
    file_type = "elf"
    first_seen = "2026-10-06 20:20:48"
  condition:
    hash.sha256(0, filesize) == "3feed21d01cd1f34f6c9dec6e7115a94865e4e2dc76002c6ef2384e461993081"
}

rule MalwareBazaar_Mirai_076_e634abc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e634abc411327b6c0f341f88838a443a227419ef1d75244fe3ce5c1596e7a0b2"
    family = "Mirai"
    file_name = "gnome"
    file_type = "elf"
    first_seen = "2026-10-06 19:56:04"
  condition:
    hash.sha256(0, filesize) == "e634abc411327b6c0f341f88838a443a227419ef1d75244fe3ce5c1596e7a0b2"
}

rule MalwareBazaar_unknown_077_a7ec2937
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7ec293736b98f2eb2dd24801d3b958b2c2b33553bcf975c6e654861fd86422f"
    family = "unknown"
    file_name = "rooming.hta"
    file_type = "hta"
    first_seen = "2026-10-06 19:40:10"
  condition:
    hash.sha256(0, filesize) == "a7ec293736b98f2eb2dd24801d3b958b2c2b33553bcf975c6e654861fd86422f"
}

rule MalwareBazaar_unknown_078_f94c1aaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94c1aaa08179bda1d9a6be54cf159ee9e80a92fcd01e6a6ecf6dbf434f9513e"
    family = "unknown"
    file_name = "SecuriteInfo.com.X97M.DownLoader.2343.12252.12934"
    file_type = "xlsx"
    first_seen = "2026-10-06 19:36:15"
  condition:
    hash.sha256(0, filesize) == "f94c1aaa08179bda1d9a6be54cf159ee9e80a92fcd01e6a6ecf6dbf434f9513e"
}

rule MalwareBazaar_unknown_079_f7553d50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7553d5037de0393da84fed09eaa9908768b91044ef42c8614a8c7efac81fe7c"
    family = "unknown"
    file_name = "CS2 Aether Tool.exe"
    file_type = "exe"
    first_seen = "2026-10-06 19:28:19"
  condition:
    hash.sha256(0, filesize) == "f7553d5037de0393da84fed09eaa9908768b91044ef42c8614a8c7efac81fe7c"
}

rule MalwareBazaar_Gafgyt_080_eff4cbad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff4cbad70d1a0cbf9c296ebb2ea16e25cf52cb961b278501081bd6a376f1652"
    family = "Gafgyt"
    file_name = "telnetd"
    file_type = "elf"
    first_seen = "2026-10-06 19:20:17"
  condition:
    hash.sha256(0, filesize) == "eff4cbad70d1a0cbf9c296ebb2ea16e25cf52cb961b278501081bd6a376f1652"
}

rule MalwareBazaar_unknown_081_649695cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649695cc337c50bf71bbf43b6c976d7937d6c504332db83e7d9e71213a0ac728"
    family = "unknown"
    file_name = "WindowsSecurityUpdate.exe"
    file_type = "exe"
    first_seen = "2026-10-06 19:04:06"
  condition:
    hash.sha256(0, filesize) == "649695cc337c50bf71bbf43b6c976d7937d6c504332db83e7d9e71213a0ac728"
}

rule MalwareBazaar_unknown_082_97a7cb91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a7cb9173bcef716a999ff6968805d416c02ccfa29a5f4f6fcc31e9a9878fba"
    family = "unknown"
    file_name = "macho_97a7cb9173bc.bin"
    file_type = "macho"
    first_seen = "2026-10-06 19:00:41"
  condition:
    hash.sha256(0, filesize) == "97a7cb9173bcef716a999ff6968805d416c02ccfa29a5f4f6fcc31e9a9878fba"
}

rule MalwareBazaar_unknown_083_c10b05f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c10b05f1e4780e30f31f78777b682093c7e3733d31a3cca229ba684865faa621"
    family = "unknown"
    file_name = "Vlmc.exe"
    file_type = "exe"
    first_seen = "2026-10-06 18:39:01"
  condition:
    hash.sha256(0, filesize) == "c10b05f1e4780e30f31f78777b682093c7e3733d31a3cca229ba684865faa621"
}

rule MalwareBazaar_Mirai_084_1b6ad824
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b6ad824dde015ae8a70edc40ab20d85148c4377a8b8b0315b80749c3fe799d2"
    family = "Mirai"
    file_name = "vcimanagement.m68k"
    file_type = "elf"
    first_seen = "2026-10-06 18:35:53"
  condition:
    hash.sha256(0, filesize) == "1b6ad824dde015ae8a70edc40ab20d85148c4377a8b8b0315b80749c3fe799d2"
}

rule MalwareBazaar_unknown_085_42b9903e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251"
    family = "unknown"
    file_name = "42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251.sh"
    file_type = "sh"
    first_seen = "2026-10-06 18:20:49"
  condition:
    hash.sha256(0, filesize) == "42b9903e577d1744e27310200b778f7dc008ae73b7a4715249c9183565788251"
}

rule MalwareBazaar_unknown_086_d5b96f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b96f051559b216d0fdc3571e606105ceab4790e9e29bfd4ffd75b89a0af69b"
    family = "unknown"
    file_name = "rooming.hta"
    file_type = "hta"
    first_seen = "2026-10-06 18:11:29"
  condition:
    hash.sha256(0, filesize) == "d5b96f051559b216d0fdc3571e606105ceab4790e9e29bfd4ffd75b89a0af69b"
}

rule MalwareBazaar_unknown_087_07f9ea17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f9ea17427378edcff042f019680f4149b0c34a1b589b8621a30e2c8e240310"
    family = "unknown"
    file_name = "fuck_niggers_2.hta"
    file_type = "hta"
    first_seen = "2026-10-06 18:06:18"
  condition:
    hash.sha256(0, filesize) == "07f9ea17427378edcff042f019680f4149b0c34a1b589b8621a30e2c8e240310"
}

rule MalwareBazaar_unknown_088_265fb1b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "265fb1b0dc44cfa05b94d2802189cf7aeb2a42905646f28453cf1e16941789dc"
    family = "unknown"
    file_name = "MO_TA_VIEC_LAM_P5.zip"
    file_type = "zip"
    first_seen = "2026-10-06 17:46:18"
  condition:
    hash.sha256(0, filesize) == "265fb1b0dc44cfa05b94d2802189cf7aeb2a42905646f28453cf1e16941789dc"
}

rule MalwareBazaar_unknown_089_4837b7a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4837b7a6c207af2dc9e3ef2b905cbc0d977efa3a4f31a85ca8ad5339704aae87"
    family = "unknown"
    file_name = "zoom-update.msc"
    file_type = "msc"
    first_seen = "2026-10-06 17:37:31"
  condition:
    hash.sha256(0, filesize) == "4837b7a6c207af2dc9e3ef2b905cbc0d977efa3a4f31a85ca8ad5339704aae87"
}

rule MalwareBazaar_RustyStealer_090_11d7da51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d7da51a1d765e6f6946b27566876a5c42e4d157bdb2c9f45dc579c87417f31"
    family = "RustyStealer"
    file_name = "Havene catalog.pdf.exe"
    file_type = "exe"
    first_seen = "2026-10-06 17:34:24"
  condition:
    hash.sha256(0, filesize) == "11d7da51a1d765e6f6946b27566876a5c42e4d157bdb2c9f45dc579c87417f31"
}

rule MalwareBazaar_Mirai_091_b4e2a808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4e2a808f57fc407bc2c7b7d3c6c42ca0e358d23bc6c6d4b49865ba3abd2d237"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-06 17:31:29"
  condition:
    hash.sha256(0, filesize) == "b4e2a808f57fc407bc2c7b7d3c6c42ca0e358d23bc6c6d4b49865ba3abd2d237"
}

rule MalwareBazaar_Mirai_092_b4991411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4991411975fbe9a19516114f5ad0c3dd897d3f998cf741db4661a09ba624cc1"
    family = "Mirai"
    file_name = "sarm64"
    file_type = "elf"
    first_seen = "2026-10-06 17:21:23"
  condition:
    hash.sha256(0, filesize) == "b4991411975fbe9a19516114f5ad0c3dd897d3f998cf741db4661a09ba624cc1"
}

rule MalwareBazaar_Mirai_093_ba8ea35f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba8ea35fb544e00be375e3ff080e5ed10af088c27f7cf12ee283e5351d740f2e"
    family = "Mirai"
    file_name = "sarm64"
    file_type = "elf"
    first_seen = "2026-10-06 17:21:13"
  condition:
    hash.sha256(0, filesize) == "ba8ea35fb544e00be375e3ff080e5ed10af088c27f7cf12ee283e5351d740f2e"
}

rule MalwareBazaar_unknown_094_d14e4547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14e45479e964178f165e330954120cf0e3c26714af9a4339ccd41aa017a4c83"
    family = "unknown"
    file_name = "INQUIRY -2026-17085.js"
    file_type = "js"
    first_seen = "2026-10-06 17:14:29"
  condition:
    hash.sha256(0, filesize) == "d14e45479e964178f165e330954120cf0e3c26714af9a4339ccd41aa017a4c83"
}

rule MalwareBazaar_unknown_095_197f763b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0"
    family = "unknown"
    file_name = "9a.bat"
    file_type = "bat"
    first_seen = "2026-10-06 17:01:37"
  condition:
    hash.sha256(0, filesize) == "197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0"
}

rule MalwareBazaar_Mirai_096_bef45f3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bef45f3b51f4d42e2f0d5c4b44946d11e002f2b589be2fdf3e5ed2d0aad68ef3"
    family = "Mirai"
    file_name = "vcimanagement.ppc"
    file_type = "elf"
    first_seen = "2026-10-06 16:59:39"
  condition:
    hash.sha256(0, filesize) == "bef45f3b51f4d42e2f0d5c4b44946d11e002f2b589be2fdf3e5ed2d0aad68ef3"
}

rule MalwareBazaar_Mirai_097_90438e02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90438e02b7f3d87ba0d832308efe5f20d895713d52f614fd98e7fc3eb643b3b9"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-10-06 16:59:37"
  condition:
    hash.sha256(0, filesize) == "90438e02b7f3d87ba0d832308efe5f20d895713d52f614fd98e7fc3eb643b3b9"
}

rule MalwareBazaar_Mirai_098_e85c05fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e85c05fb2f529fa7d8c02cd8b28a58b375e61c288c568fe531b5bd21d48df4c5"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-10-06 16:54:21"
  condition:
    hash.sha256(0, filesize) == "e85c05fb2f529fa7d8c02cd8b28a58b375e61c288c568fe531b5bd21d48df4c5"
}

rule MalwareBazaar_Mirai_099_5e245329
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e2453297f38a5965bd9cbb86eeebf81001044e842a65c7ff3fcdbeefc565a19"
    family = "Mirai"
    file_name = "sora.mpsl"
    file_type = "elf"
    first_seen = "2026-10-06 16:54:06"
  condition:
    hash.sha256(0, filesize) == "5e2453297f38a5965bd9cbb86eeebf81001044e842a65c7ff3fcdbeefc565a19"
}

rule MalwareBazaar_Mirai_100_9f2ccb39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f2ccb39fd57752cdcee1b20489d08fcfd78167ebf43eda09e14eb17f32d81d2"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-10-06 16:49:20"
  condition:
    hash.sha256(0, filesize) == "9f2ccb39fd57752cdcee1b20489d08fcfd78167ebf43eda09e14eb17f32d81d2"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

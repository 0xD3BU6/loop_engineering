# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-21

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 648 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 648 |
| Unique family labels | 7 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 57 |
| unknown | 36 |
| Gh0stRAT | 2 |
| RemusStealer | 2 |
| Prometei | 1 |
| ValleyRAT | 1 |
| NanoCore | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 60 |
| exe | 19 |
| sh | 15 |
| unknown | 2 |
| msi | 1 |
| iso | 1 |
| ps1 | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `f76ea26f6031ebd6`

| Field | Value |
|---|---|
| SHA-256 | `f76ea26f6031ebd63e849b1c41bf6a6255d8291e47482617557fd73154ce445f` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-07-21 03:43:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `927df5bb8cf28f405f40a6bdb0e8d0ad` |
| SHA-1 | `b6a46b1086dddad647f980c7ed127b9082033d60` |
| SHA-256 | `f76ea26f6031ebd63e849b1c41bf6a6255d8291e47482617557fd73154ce445f` |
| SHA3-384 | `3e95ce18034b84d20b4e40c13717df9cab8bfacc9121755eacda4cbb799ca3a9601312626457c45c75c7f2c16bf036aa` |
| TLSH | `T183E33B85EA408A13C0D61776FAAF41493322DB55E3DB73079D189FF43FC6A9E0E26606` |
| TELFHASH | `t114211471173596256e60ce9c99eda771122887131389ff33df3584eca50909ee63ac4f` |
| SSDEEP | `3072:sqlhEFZBB9qPoLmpMguHcUlVUHalw7WguH0vsfC0XxmjX5Xa/NOL9eXgIncdV82J:sqlhEFZBTqPoLmpMguHcUlVUHalw7WgF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_f76ea26f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f76ea26f6031ebd63e849b1c41bf6a6255d8291e47482617557fd73154ce445f"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-21 03:43:52"
  condition:
    hash.sha256(0, filesize) == "f76ea26f6031ebd63e849b1c41bf6a6255d8291e47482617557fd73154ce445f"
}
```

### Sample 2: `9650b84c44403dec`

| Field | Value |
|---|---|
| SHA-256 | `9650b84c44403decb656beab529c70fc1ec02bafa9d70f7694c381998bbea22d` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-07-21 03:42:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `050ca58f47acc067ac400b9f9ab07fd5` |
| SHA-1 | `d2298aad53870adadd0a8c7700748586fc689c9e` |
| SHA-256 | `9650b84c44403decb656beab529c70fc1ec02bafa9d70f7694c381998bbea22d` |
| SHA3-384 | `9baea4fa2782f92250ab7e49e5330c9f7718585f356db113b1e823c9a070d62d0c6c480b0d499003c9942ec8eecf4ca6` |
| TLSH | `T1E633027257AE6DE151B09737FC32EC1A669C17F8996B30DA2CF09A1973C58014EF2782` |
| SSDEEP | `1536:d9O/ZMAXIxNUk07LcPqF1aBexo4opKZb5:d9O/ZNKy/LGqFUFU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_9650b84c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9650b84c44403decb656beab529c70fc1ec02bafa9d70f7694c381998bbea22d"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-21 03:42:53"
  condition:
    hash.sha256(0, filesize) == "9650b84c44403decb656beab529c70fc1ec02bafa9d70f7694c381998bbea22d"
}
```

### Sample 3: `108ef7e628d7a20b`

| Field | Value |
|---|---|
| SHA-256 | `108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc` |
| Family label | `unknown` |
| File name | `wmaines_rmm_v2.5.0.67_oid3f4ebaba-6585-48d9-82be-4e2f3124e8b3_bid8etMwZceBUaX5sZKZactsw.exe` |
| File type | `exe` |
| First seen | `2026-07-21 03:37:21` |
| Reporter | `ppt_lol` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `386529af136fe96a23da6aaa39711e2b` |
| SHA-1 | `f34330d4c6e0aa978dc3af40360c14b31ad51127` |
| SHA-256 | `108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc` |
| SHA3-384 | `00b477773896c21aeca2c63acf8c1b1d4f5f1efc820a80593f232af03a0c64be6da25af4c4097cd70b289fc5087ac44b` |
| IMPHASH | `12082e77cfc7e34f96f21f95764c8ac3` |
| TLSH | `T1E30733907CA4F70EDCA8D438C97053F041EB0EEDF6769017A4A27E6237B7293D69A845` |
| SSDEEP | `393216:Sz0LnfhNw32VNelklzfhSecSpv5JwuFUvmB8leDOgwtEI0ppjagOibnaE4qX5y:SzMnsA88tSxe5JhUvmO0DOgXOgOijacQ` |
| ICON-DHASH | `4d71736169453333` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_108ef7e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc"
    family = "unknown"
    file_name = "wmaines_rmm_v2.5.0.67_oid3f4ebaba-6585-48d9-82be-4e2f3124e8b3_bid8etMwZceBUaX5sZKZactsw.exe"
    file_type = "exe"
    first_seen = "2026-07-21 03:37:21"
  condition:
    hash.sha256(0, filesize) == "108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc"
}
```

### Sample 4: `628293254de28ceb`

| Field | Value |
|---|---|
| SHA-256 | `628293254de28ceb33d8905f928da292d0e31897a8825bbccaefed10536b0a9e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-21 02:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34692b5f1b71ecaa289c1c152999ad17` |
| SHA-1 | `337219a925626b7d61994a8a17905bb30e288ebd` |
| SHA-256 | `628293254de28ceb33d8905f928da292d0e31897a8825bbccaefed10536b0a9e` |
| SHA3-384 | `1b367231348b89a5709db9f7b4ad21287ceb6439c1f95e90c90e242760c7be3dc0173bd07f5082dcba10e5158cd877a1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1FCE633281BD4527ED673007CAD9622EBD8AE74700B71C9EF0BA887659C571B14E3E723` |
| SSDEEP | `393216:IaY+eHEzv5Ej3AhjoMH6uFm7UXtgxNhXMCHWUjXvcuI3/PGTAI:fYxEt23AddauFGUXtg3hXMb8XkH/O7` |
| ICON-DHASH | `e86865e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_62829325
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "628293254de28ceb33d8905f928da292d0e31897a8825bbccaefed10536b0a9e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 02:52:09"
  condition:
    hash.sha256(0, filesize) == "628293254de28ceb33d8905f928da292d0e31897a8825bbccaefed10536b0a9e"
}
```

### Sample 5: `12552a110d5bcb5f`

| Field | Value |
|---|---|
| SHA-256 | `12552a110d5bcb5f593c40df2e78ce7253cc6103b245adb3029b15d44026f3c0` |
| Family label | `unknown` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-21 02:24:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fd762fe2e87352ffa725d1bdd682d32` |
| SHA-1 | `f9c97c0af0cbaed6854b7c9ad24010ca92160dcd` |
| SHA-256 | `12552a110d5bcb5f593c40df2e78ce7253cc6103b245adb3029b15d44026f3c0` |
| SHA3-384 | `dc57378c6fde849dd55e4c4c239f2881f96e8985084fa44840caa08ce128d29dffe21a30bea9ed16958cfe401795926a` |
| TLSH | `T118E33B45FC509B26C6D7227BFF4E428D772A1768D3EE320399256F20379A85B0E77242` |
| TELFHASH | `t1fce06137df201f9c1bd49136c0f5e11c41b5318a1b214008079daecb4b9b2cdb52853f` |
| SSDEEP | `1536:B8fp4C9pYOKQG/qAC8p8o8PFlhN9IPhHetADL/7T5xAzFo4ZXO2JtsSTdB2lE6wy:B/CPfKCJNCEtAn7FazF79qSBHEd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_12552a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12552a110d5bcb5f593c40df2e78ce7253cc6103b245adb3029b15d44026f3c0"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-21 02:24:48"
  condition:
    hash.sha256(0, filesize) == "12552a110d5bcb5f593c40df2e78ce7253cc6103b245adb3029b15d44026f3c0"
}
```

### Sample 6: `44f4620c1f239c8a`

| Field | Value |
|---|---|
| SHA-256 | `44f4620c1f239c8abba7f0b04b63f2238ed917f1285ebc416d2c2d21adb3a6cf` |
| Family label | `unknown` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-21 02:24:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcc38510f3241c82412f875c49cbd216` |
| SHA-1 | `ad809e10528e0ac74b491f2a9f21c2853243b5b1` |
| SHA-256 | `44f4620c1f239c8abba7f0b04b63f2238ed917f1285ebc416d2c2d21adb3a6cf` |
| SHA3-384 | `c7c766df33d157dc19e3e17636c895fddad743b93bd699a91d4c8cb66e498c2400f885fb27e7ff129ff72d4c92138399` |
| TLSH | `T1FD43F1324EB39C3181A12439F4358E2B3E6749B0A46B76B5229F997D84EC58532ED3CD` |
| SSDEEP | `1536:P92I0ScfFmRNzOy/WpzM//IoMjrIDKj0C:QI0duzOy/WpI/gBj8tC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_44f4620c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44f4620c1f239c8abba7f0b04b63f2238ed917f1285ebc416d2c2d21adb3a6cf"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-21 02:24:37"
  condition:
    hash.sha256(0, filesize) == "44f4620c1f239c8abba7f0b04b63f2238ed917f1285ebc416d2c2d21adb3a6cf"
}
```

### Sample 7: `db99e7a9d7ba73fb`

| Field | Value |
|---|---|
| SHA-256 | `db99e7a9d7ba73fbdcf2e0c9d6a7efb496beb29f87d00ddccff1825c641d1bf4` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-21 02:19:15` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7957bf772a86d49fde270c135de93bf4` |
| SHA-1 | `466c9fadc4bdaff7422b479fdb77eace85a8e88e` |
| SHA-256 | `db99e7a9d7ba73fbdcf2e0c9d6a7efb496beb29f87d00ddccff1825c641d1bf4` |
| SHA3-384 | `4206ac85024045568013e686dd75c163e32485b72b9cad48b63242fbf38bbd5e33a64e2ee635914a86eca94fbcd58a1f` |
| TLSH | `T18C236C651A857C149E99C4371D7E2F0CB9AD43E6320852DE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:CVEJVIhtMV9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:YEJ2MGcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_db99e7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db99e7a9d7ba73fbdcf2e0c9d6a7efb496beb29f87d00ddccff1825c641d1bf4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-21 02:19:15"
  condition:
    hash.sha256(0, filesize) == "db99e7a9d7ba73fbdcf2e0c9d6a7efb496beb29f87d00ddccff1825c641d1bf4"
}
```

### Sample 8: `dc745c186d00780c`

| Field | Value |
|---|---|
| SHA-256 | `dc745c186d00780cc85dd82adf4186441935ebc6547e375d778eaffb5dbe9305` |
| Family label | `unknown` |
| File name | `softinst.873360017.msi` |
| File type | `msi` |
| First seen | `2026-07-21 02:16:36` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41149b65e88f1807a83269dc1535f6ed` |
| SHA-1 | `fa6bcae7978bc960c587fb2682fa5ad156962e0a` |
| SHA-256 | `dc745c186d00780cc85dd82adf4186441935ebc6547e375d778eaffb5dbe9305` |
| SHA3-384 | `82ec93a16c389be3889ae8564f0bdcfeef054c9d4062207c5fbca6cbcb308fdcbebf525e7e48c97ca95043842f8e6090` |
| TLSH | `T18F8633E4BC8A2331C1ABD3B19646357DB02C7FE1BFA78C437AE03B281E726169075655` |
| SSDEEP | `196608:EK+X5nrYVBbqyTSA2EgREpbF1l3MkXloeNuH2iPupiRrey:0pnrYTqyuA28nDloeYWm+3y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_dc745c18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc745c186d00780cc85dd82adf4186441935ebc6547e375d778eaffb5dbe9305"
    family = "unknown"
    file_name = "softinst.873360017.msi"
    file_type = "msi"
    first_seen = "2026-07-21 02:16:36"
  condition:
    hash.sha256(0, filesize) == "dc745c186d00780cc85dd82adf4186441935ebc6547e375d778eaffb5dbe9305"
}
```

### Sample 9: `941bae04b8307eff`

| Field | Value |
|---|---|
| SHA-256 | `941bae04b8307eff2faa47f60c59298717d218e06c4e716ff576dc9cf0363ddb` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-21 01:52:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dceeadcf0b77afca511c5a8caf653b0f` |
| SHA-1 | `87f75ccce73b499013e72bac644f174f21d82027` |
| SHA-256 | `941bae04b8307eff2faa47f60c59298717d218e06c4e716ff576dc9cf0363ddb` |
| SHA3-384 | `533a2a342a21979a9700dd3aba69fd3c702d0cd526547c4b292f7b11e79df03eb3498074a3ff7a722055d4266b0cb216` |
| TLSH | `T15801ABCAD250951085699A1E669762E0B430C3C6169B0B687FACD83DEB9CE14F16AF88` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha1a8UnMar2jF7727:e9Qp+MsxUnMaKjVC7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_941bae04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "941bae04b8307eff2faa47f60c59298717d218e06c4e716ff576dc9cf0363ddb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-21 01:52:36"
  condition:
    hash.sha256(0, filesize) == "941bae04b8307eff2faa47f60c59298717d218e06c4e716ff576dc9cf0363ddb"
}
```

### Sample 10: `26dfbed73c43b51a`

| Field | Value |
|---|---|
| SHA-256 | `26dfbed73c43b51a8b0b2136e35f78bd987aff9fd163c5c7abaeca4ce639ae17` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-21 01:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d9debe827b125fa52e76692b0d6d25a` |
| SHA-1 | `60e2f3ee0d06652eacfc71d1c36f503d68b28988` |
| SHA-256 | `26dfbed73c43b51a8b0b2136e35f78bd987aff9fd163c5c7abaeca4ce639ae17` |
| SHA3-384 | `942aa6fae9abbc742e595e4d5c15c51f300883976cdc3d759e0c397222257c9d859e7dc7ab956eeb294aabf2e7a56105` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T152E6331866F812BDDAB3513DEBB19561D0E7B03A0762CC8B5B9893B16D132E04D3E793` |
| SSDEEP | `393216:eBOvQTtRbwgL+1XPYWwC3y6bXMCHWUjXNcuI3/PGTAI:eB9BFwm+1fUCxbXMb8X6H/O7` |
| ICON-DHASH | `d4b87cbc8cc47030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_26dfbed7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26dfbed73c43b51a8b0b2136e35f78bd987aff9fd163c5c7abaeca4ce639ae17"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 01:52:08"
  condition:
    hash.sha256(0, filesize) == "26dfbed73c43b51a8b0b2136e35f78bd987aff9fd163c5c7abaeca4ce639ae17"
}
```

### Sample 11: `238938a735d49263`

| Field | Value |
|---|---|
| SHA-256 | `238938a735d49263fa104db44584978eb478d6fee9617881c60762f621715325` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-21 01:45:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1954f3708f4785957a7856dc9bd991c3` |
| SHA-1 | `d5687aebef68c95a92b00096f425a7e75e5257f3` |
| SHA-256 | `238938a735d49263fa104db44584978eb478d6fee9617881c60762f621715325` |
| SHA3-384 | `286f03bfbcdbcbcdea59d7a88434c2d4338b71cfff590ddb0767befc78063cc347ca2ef8c4659e181fdc4cf4d580b3a9` |
| TLSH | `T1EEC27C956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:u8vCB+25j6es8RXz9FYpMSUpi+20qUpi+20YQX:u8l25Jld2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_238938a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "238938a735d49263fa104db44584978eb478d6fee9617881c60762f621715325"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-21 01:45:24"
  condition:
    hash.sha256(0, filesize) == "238938a735d49263fa104db44584978eb478d6fee9617881c60762f621715325"
}
```

### Sample 12: `d321b7d4712744fe`

| Field | Value |
|---|---|
| SHA-256 | `d321b7d4712744fe03084d7a54f53836279e19b9c35426990057991146e7d9f1` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-21 01:13:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d53df1adf583a09e41e673665f819fc` |
| SHA-1 | `c00b727946875b5691a52d2cf55e7e12da1331ce` |
| SHA-256 | `d321b7d4712744fe03084d7a54f53836279e19b9c35426990057991146e7d9f1` |
| SHA3-384 | `cb767af8a2d9e6712b1bb5b63ba26696c2e86641c0387baf5d2f0687d9af92bc01431c1700e22210627319a353ed9cd6` |
| TLSH | `T199018ECA86546D0044AADA5D22EB5158F811C3CF1E5A4FB5BFEC6D3DEB95C04B03AF84` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaDjCGktCD5jCBn8CwFtx8CjX:kXCKysE2hi0ziQvZohaDj2gN1H8oX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_d321b7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d321b7d4712744fe03084d7a54f53836279e19b9c35426990057991146e7d9f1"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-21 01:13:11"
  condition:
    hash.sha256(0, filesize) == "d321b7d4712744fe03084d7a54f53836279e19b9c35426990057991146e7d9f1"
}
```

### Sample 13: `901ad9c29b0944a6`

| Field | Value |
|---|---|
| SHA-256 | `901ad9c29b0944a6af9642c4021c80f7959c8d31c7fb7b9a6216e17d12244541` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-21 01:08:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80edf28f7ec6295cda88970a79ff6efd` |
| SHA-1 | `274e382068a55f5d8a7da48436f7dd548a8888b0` |
| SHA-256 | `901ad9c29b0944a6af9642c4021c80f7959c8d31c7fb7b9a6216e17d12244541` |
| SHA3-384 | `b0150d69a512383b7fa1946094e0609ff18cebdca8ea776b25430b3a4df61cfd9018d915821ee0f27905fc84cd653121` |
| TLSH | `T14301CECA8650BD00446ADA5D62EB5294F811C3CF0E5A0FB87FDC5D2DFB99804B026F88` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaDjCGutCDljCfFn8CwBtx8ClauD:kXCKysE2hi0ziQvZohaDjEghSKj8E7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_901ad9c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "901ad9c29b0944a6af9642c4021c80f7959c8d31c7fb7b9a6216e17d12244541"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-21 01:08:59"
  condition:
    hash.sha256(0, filesize) == "901ad9c29b0944a6af9642c4021c80f7959c8d31c7fb7b9a6216e17d12244541"
}
```

### Sample 14: `e296f65108930c6e`

| Field | Value |
|---|---|
| SHA-256 | `e296f65108930c6e5d0fcd0ecd4654099dae322ce118e25fbfe01250dc8e1c29` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-21 00:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a23a2fbb43f109cd663fec1fd01b9a0d` |
| SHA-1 | `ae6c74c8decffa1e2f121d0470729f91ba9fa1a3` |
| SHA-256 | `e296f65108930c6e5d0fcd0ecd4654099dae322ce118e25fbfe01250dc8e1c29` |
| SHA3-384 | `72a8948ccc2398f0b5810f8f2a06b8e8fe5c1803efd4c0af39159d84fce0972fe90293c3223926ef127f2fe1fb011abb` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T117E633585AE511FFEA73803CD9E225E6F191BC662730C9C747A88390EE573D8897E312` |
| SSDEEP | `393216:Tl9X5739W3ij5er2egvfTv326hCABvsFxXhnDlXMCHWUjXgcuI3/PGTAI:TvpBW3tZgHsF7nDlXMb8X1H/O7` |
| ICON-DHASH | `007860c0dcf9f100` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_e296f651
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e296f65108930c6e5d0fcd0ecd4654099dae322ce118e25fbfe01250dc8e1c29"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 00:52:08"
  condition:
    hash.sha256(0, filesize) == "e296f65108930c6e5d0fcd0ecd4654099dae322ce118e25fbfe01250dc8e1c29"
}
```

### Sample 15: `748f3c2705750d77`

| Field | Value |
|---|---|
| SHA-256 | `748f3c2705750d776056a58fff76a54251d252f537b5000d54aab46ab4f56db2` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-21 00:52:05` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e1959009b0d2e19f3e7f567a42cb3ae` |
| SHA-1 | `796437e39ca0032afe6c7d61371eddcdf217d8f4` |
| SHA-256 | `748f3c2705750d776056a58fff76a54251d252f537b5000d54aab46ab4f56db2` |
| SHA3-384 | `bdd56bbb0cea01ee5e77549687a406f641e40f92c9229dfabbc773aecd5c81cbf4c3dcf3a65e61541b7e8e929f742feb` |
| TLSH | `T171C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC15F9CC618B1A` |
| SSDEEP | `768:vQ8vCB+25j6es8RWYxi9FYpMSUpi+20qUpi+20YQX:vQ8l25JRxEd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_748f3c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "748f3c2705750d776056a58fff76a54251d252f537b5000d54aab46ab4f56db2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-21 00:52:05"
  condition:
    hash.sha256(0, filesize) == "748f3c2705750d776056a58fff76a54251d252f537b5000d54aab46ab4f56db2"
}
```

### Sample 16: `4413558056659da0`

| Field | Value |
|---|---|
| SHA-256 | `4413558056659da02a67fb77b30fd223e090468899ba2714ebdf6e0a9b9ff9bc` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-21 00:30:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d34577be6469d3d8f366ad160bb57cf7` |
| SHA-1 | `54ca801a8cc67ca810ac1556fe10d54771af4149` |
| SHA-256 | `4413558056659da02a67fb77b30fd223e090468899ba2714ebdf6e0a9b9ff9bc` |
| SHA3-384 | `f65b806d49a9ae7d9a1a7543758da5319fced3b599ba4ce8e2687952a712c21c14e5bec51f2c30bb6058a80a28a4f525` |
| TLSH | `T131236C6516857C14AE99C4365C7F2F0CB9AD43E6314492EE7FCE3CF28C4A6AD920871D` |
| SSDEEP | `768:4r9NyXsZztCy29GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:mHusZ5cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_44135580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4413558056659da02a67fb77b30fd223e090468899ba2714ebdf6e0a9b9ff9bc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-21 00:30:48"
  condition:
    hash.sha256(0, filesize) == "4413558056659da02a67fb77b30fd223e090468899ba2714ebdf6e0a9b9ff9bc"
}
```

### Sample 17: `847866fd99c7898e`

| Field | Value |
|---|---|
| SHA-256 | `847866fd99c7898e27069e3f0dce04c6e5e39ba51bb2a86ccc086d51b4320b95` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-21 00:26:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c775fa89dbf20b6b10d609ce8b44703` |
| SHA-1 | `42fd8ea509f26c9fa6ab6c841bda08162021b4dd` |
| SHA-256 | `847866fd99c7898e27069e3f0dce04c6e5e39ba51bb2a86ccc086d51b4320b95` |
| SHA3-384 | `ca4af2f66be4d68ba37ca986997566246767b644de04b8ca44107c612337372a643f04baf4bed1f8a0d6ee226e117b37` |
| TLSH | `T187A36CD6F243D4F6DC2605346173FF375D72D5BA2329C9C3D3E89A36A822641C91AA8C` |
| TELFHASH | `t1643103f962761cd4abd09d02f20e6b60be0e7b77642437a305a35934316a992937bc3c` |
| SSDEEP | `1536:+XeCa/WojVnyrbQM31JP71RTS2ASm6zuWPfSZt6cJasl70QhL3SElCXDBE:5jNmlt71RulYTfOtXJnh0MlCzBE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_847866fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847866fd99c7898e27069e3f0dce04c6e5e39ba51bb2a86ccc086d51b4320b95"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-21 00:26:15"
  condition:
    hash.sha256(0, filesize) == "847866fd99c7898e27069e3f0dce04c6e5e39ba51bb2a86ccc086d51b4320b95"
}
```

### Sample 18: `3e94cbf359f2bef4`

| Field | Value |
|---|---|
| SHA-256 | `3e94cbf359f2bef4c8ef6dd71108455108c00c3b917aadb2015c176d60bbdd9d` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-21 00:24:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88050b361ee567b5f6ea2c5f879ae964` |
| SHA-1 | `76b8eb6fd5cbdaa115b7ae5eb31c6535ccf97288` |
| SHA-256 | `3e94cbf359f2bef4c8ef6dd71108455108c00c3b917aadb2015c176d60bbdd9d` |
| SHA3-384 | `572837e2a3bab1147c008d0cc789fdc0f49220823c98cec57e2988b92deccadc3d2eab1b6f4db0c23822a24ff0d01242` |
| TLSH | `T10B23F143F66A825EC079997804DF7B07084AB24E30F0796C6F943275AEC5F562B392E7` |
| SSDEEP | `768:rN6DL9KkxEBSt/Nsq8ZUjCMnltn6ZdEl6ZP6N1kwaDOtXvSDtL1WjlxFpfCtuf6r:pQBKkxEot/NsbZUTnL6pF64wcOtfGWL+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_3e94cbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e94cbf359f2bef4c8ef6dd71108455108c00c3b917aadb2015c176d60bbdd9d"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-21 00:24:37"
  condition:
    hash.sha256(0, filesize) == "3e94cbf359f2bef4c8ef6dd71108455108c00c3b917aadb2015c176d60bbdd9d"
}
```

### Sample 19: `b48be96d4178766e`

| Field | Value |
|---|---|
| SHA-256 | `b48be96d4178766e340c72991622f74f66b10791742edc9e326ea77812261288` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.sh4` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f29dd3384847be0e3a3dbcf1b5425b0f` |
| SHA-1 | `8cd5b2570581dc70d358592a45c3c8fef62534ce` |
| SHA-256 | `b48be96d4178766e340c72991622f74f66b10791742edc9e326ea77812261288` |
| SHA3-384 | `cd0b373725a508cb1f6d6bf91a63033dc328ae93e5932cbfd0aa48e7d1559489fa18d55ca9fa6dba3507c7c8990a626a` |
| TLSH | `T105739D76D0B86D98C5148A34A6AC99B88B17A40467A37FF2C6C1CF654047EFCF2147FA` |
| SSDEEP | `1536:P/kM1DnBApwt1N0Haa+9mUESf9RwU9K4H00lRCi8G:PMMxnip4cxS1qkdH00D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_b48be96d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48be96d4178766e340c72991622f74f66b10791742edc9e326ea77812261288"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.sh4"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:48"
  condition:
    hash.sha256(0, filesize) == "b48be96d4178766e340c72991622f74f66b10791742edc9e326ea77812261288"
}
```

### Sample 20: `ac93242580236d6e`

| Field | Value |
|---|---|
| SHA-256 | `ac93242580236d6e3be41e03c6dd00aee95c9b0921cfa9356dc307b5006f9e69` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.arm` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d365edc46eccf6dfefa8c152dc72581f` |
| SHA-1 | `8aecd09641f8c894beb7d1c474d66960e8ac9059` |
| SHA-256 | `ac93242580236d6e3be41e03c6dd00aee95c9b0921cfa9356dc307b5006f9e69` |
| SHA3-384 | `89e20f4bde973d414a9a66c08f00188bffeed0e816714301cd028ad9ce90e36cbbacc869bd969e407755c04927eb0479` |
| TLSH | `T1BF930782BC81EA16C7D0137BFA6F108E331567D8E1DA3242DD251FA47BCA81F0D6B656` |
| TELFHASH | `t13b418e27ff961acca7ef426d61a5a4191aec34dc1724148a9f3c738f49029c6742e527` |
| SSDEEP | `1536:tBywrO+bV2LkKsZCPgtAURwaxmXzsk0gDmvzdJq9xB8t46bZp67WJJwUw:tBg+bVqkAxJVQJgz84wZzJJI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_ac932425
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac93242580236d6e3be41e03c6dd00aee95c9b0921cfa9356dc307b5006f9e69"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:47"
  condition:
    hash.sha256(0, filesize) == "ac93242580236d6e3be41e03c6dd00aee95c9b0921cfa9356dc307b5006f9e69"
}
```

### Sample 21: `0ba8684a96ed2575`

| Field | Value |
|---|---|
| SHA-256 | `0ba8684a96ed25751f1cee251f68437c9030725f8bbebb0bbedad4454ffdea34` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.arm5` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2eaf355629ace12813019e2b59dd7038` |
| SHA-1 | `9d80ccb503ca463e7c3c8c351da6ed8928388600` |
| SHA-256 | `0ba8684a96ed25751f1cee251f68437c9030725f8bbebb0bbedad4454ffdea34` |
| SHA3-384 | `3f836a659f264d73917a44cb47f7f88573065ef8dbf1bf98561e14a1660fd7d5f087f596f512d9da73b315f79eb38b91` |
| TLSH | `T143831982BC41A629C7D0137BEAAF508E3311B7DDD1DA3242DC254FA47ACA91F0D67B46` |
| TELFHASH | `t10ce07d00fc75871c58db9a74dddd07b49500321250574b00cf10d6f0c83f444e308d5e` |
| SSDEEP | `1536:yPjwUUaianjKST+TegqUkyKNXECsvkUEwYCB8t46zG1neU:yPUUUazKeCIyELy84MG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_0ba8684a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ba8684a96ed25751f1cee251f68437c9030725f8bbebb0bbedad4454ffdea34"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm5"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:45"
  condition:
    hash.sha256(0, filesize) == "0ba8684a96ed25751f1cee251f68437c9030725f8bbebb0bbedad4454ffdea34"
}
```

### Sample 22: `12f1d677a4f4dd24`

| Field | Value |
|---|---|
| SHA-256 | `12f1d677a4f4dd24a1f21cb02d9dfd0eb5cdc58c69024efe3eb66ebd1fa3562a` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.arm7` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8316bec51a88000b6bb7e520271e1b66` |
| SHA-1 | `6cef4b1801346487c9794c9831a0a3e156c37762` |
| SHA-256 | `12f1d677a4f4dd24a1f21cb02d9dfd0eb5cdc58c69024efe3eb66ebd1fa3562a` |
| SHA3-384 | `915fa45430f62dc130b0f2d9219b243f552d8ee84a6701f6d8cd569bfae65012847939823e8096df94fd53b1c501b156` |
| TLSH | `T157F35D86EA408A13C4C61777FAAF014D3322E759E3DB73068D185FB43F86A5E4E67606` |
| TELFHASH | `t10721dfb69b21573a5a61cc5489ee53b2162c97166389ff33ef34848c20190dee63bc5f` |
| SSDEEP | `3072:3PFsu+bVZFpfnHpKhjiYq5YYujSrwGy/tBF1EDfX6OxM/9a8cdAr:f2u+bVZ/nHwMgSrwGy/HF0fKQM/9aldQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_12f1d677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f1d677a4f4dd24a1f21cb02d9dfd0eb5cdc58c69024efe3eb66ebd1fa3562a"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm7"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:44"
  condition:
    hash.sha256(0, filesize) == "12f1d677a4f4dd24a1f21cb02d9dfd0eb5cdc58c69024efe3eb66ebd1fa3562a"
}
```

### Sample 23: `f56343d2afffab61`

| Field | Value |
|---|---|
| SHA-256 | `f56343d2afffab61cfb5eca2a2b47a133a1f936843eba0d061f0ddaaf89d26ce` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.x86` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80077107ca71e9fe5aa10be23e2d2b0a` |
| SHA-1 | `eeb3b5c046c7aaa37389684d14e914eb7139c269` |
| SHA-256 | `f56343d2afffab61cfb5eca2a2b47a133a1f936843eba0d061f0ddaaf89d26ce` |
| SHA3-384 | `66fc80d3828562429bb25443a62816563af5bd8d6250e44866ac11d109809bb5940dccc0347e5e009e9a3b7860495ac6` |
| TLSH | `T19B733AC9B5C3F8F4EC040A392177EF319E77E13BA129DD8BE7D96623A941342941229D` |
| TELFHASH | `t1c811e37d2b351c98afc0d913b24ed6345d5cfb7b21607ab719b225291162882437fd3c` |
| SSDEEP | `1536:9QC/3umbutmUl9i1WIo27ozS9Lo/b2+gJymeMlitPWmM18HR5D4WRouZbqeqVr5g:9Qu3umbutmUl9lIlkeJoT2hJymeMlite` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_f56343d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f56343d2afffab61cfb5eca2a2b47a133a1f936843eba0d061f0ddaaf89d26ce"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.x86"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:42"
  condition:
    hash.sha256(0, filesize) == "f56343d2afffab61cfb5eca2a2b47a133a1f936843eba0d061f0ddaaf89d26ce"
}
```

### Sample 24: `6497eed5be632771`

| Field | Value |
|---|---|
| SHA-256 | `6497eed5be632771c4022363b485c448a55912ca75d08ba5213581b4811f7e43` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.spc` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef3bb4565b24327d3cab1d043736f1d2` |
| SHA-1 | `f5cc56c6f5a538a08b19b5d10bfd10916056374f` |
| SHA-256 | `6497eed5be632771c4022363b485c448a55912ca75d08ba5213581b4811f7e43` |
| SHA3-384 | `9cdcbbbcde23922e8c2b5c86ae4909dbf6a58fc5979ba270791189896cccabaeb15706e462ecafb7d243dc991eeb044a` |
| TLSH | `T1B7934A25687A2E17C8D4A23E11F78752F2F5370E24B0C66E7D760F8EFF15680A5462B2` |
| SSDEEP | `1536:1KFdSaiZ2vPhnKORFS5P+lSMrhJ3HWwJnV6WO7HauvAx8:WNrZKl1NM9J32wJnV6WO7DvD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_6497eed5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6497eed5be632771c4022363b485c448a55912ca75d08ba5213581b4811f7e43"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.spc"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:41"
  condition:
    hash.sha256(0, filesize) == "6497eed5be632771c4022363b485c448a55912ca75d08ba5213581b4811f7e43"
}
```

### Sample 25: `daa5fdf5ba522771`

| Field | Value |
|---|---|
| SHA-256 | `daa5fdf5ba5227719e4435960cb10a339634c8406c71b09ce9eb7f5bc53cfe3d` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.m68k` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffd36f2d0c0528990a3dcf2f8a94c5c7` |
| SHA-1 | `ca7f86d9baf89dc1b8af950acacc783c3c1534c1` |
| SHA-256 | `daa5fdf5ba5227719e4435960cb10a339634c8406c71b09ce9eb7f5bc53cfe3d` |
| SHA3-384 | `86452d2d5da04e3088bd50ecb66ba3708a60903d369883acd1922b3fdf9e016d467d5297218e4d3045ffab7cb0383c04` |
| TLSH | `T127833B9AB4019E6CF98BDAF940224E0DF92163415B530F27A76BFDE33D620A5DE07C85` |
| SSDEEP | `1536:Qg8Bj6jeSzhScH6cfOBaXgkWkTO+FGOtWnkMtnzbBJ8RsV:iIScacfGwgeTvFYdnzdh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_daa5fdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daa5fdf5ba5227719e4435960cb10a339634c8406c71b09ce9eb7f5bc53cfe3d"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.m68k"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:40"
  condition:
    hash.sha256(0, filesize) == "daa5fdf5ba5227719e4435960cb10a339634c8406c71b09ce9eb7f5bc53cfe3d"
}
```

### Sample 26: `488a3dc8fc944a60`

| Field | Value |
|---|---|
| SHA-256 | `488a3dc8fc944a607f365a5b609dfd285d0f881b6446be3553c254617579bac1` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.ppc` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04b8c0c727af81f5f1e5327fd8a6a1d7` |
| SHA-1 | `5a844dd6d2952241abf13ed967d386b5c8891958` |
| SHA-256 | `488a3dc8fc944a607f365a5b609dfd285d0f881b6446be3553c254617579bac1` |
| SHA3-384 | `acf3857dbab9a00eb9f020c7383083aceab24d65f9da058b38b10359af58d2c5f6eaeda88741f3afa4831d59ffc843d6` |
| TLSH | `T155835C0173644F0BE8AA0AF5282F17E483FEED9021F4F5856A0FDB5A4235E37155AF98` |
| SSDEEP | `1536:7QHQd18Vez/S1f+39FAwFKtMzXIeoGXxTq:7TdUXReo7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_488a3dc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "488a3dc8fc944a607f365a5b609dfd285d0f881b6446be3553c254617579bac1"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.ppc"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:38"
  condition:
    hash.sha256(0, filesize) == "488a3dc8fc944a607f365a5b609dfd285d0f881b6446be3553c254617579bac1"
}
```

### Sample 27: `49665430bea49701`

| Field | Value |
|---|---|
| SHA-256 | `49665430bea49701da165dbadd6b8f99bde4d804fcae784072d2460c3c7d5b1e` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.arm6` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a16681377a71e627cf125e28a208b07a` |
| SHA-1 | `4914237b1c8115e2e24aa4780b044bc570bc071d` |
| SHA-256 | `49665430bea49701da165dbadd6b8f99bde4d804fcae784072d2460c3c7d5b1e` |
| SHA3-384 | `0ec6e2f9d97aa4fea3ed53c39637c43bdb5382509baf4f45c454402351708f8b0c2bf510aa561cd92cbe3d37eff2e7a4` |
| TLSH | `T198A32A86BC819A11C6C51377FA2F108D330267ADF2DE7262CD151F647BCA81F0E6BA56` |
| TELFHASH | `t10de02663cf240d9c5ace4a4d82dc68041be872ac7e1a84a6b6cc9f0a5412196353c10f` |
| SSDEEP | `1536:4Nnr0vpp/rFFSHs6h/d43AtnA78bPiqimKF/yqtBiJ70q5duUndOw7nizCIGiHmc:m0h9FEHztfNDbPf9waYq5MUnjghZmN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_49665430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49665430bea49701da165dbadd6b8f99bde4d804fcae784072d2460c3c7d5b1e"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm6"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:37"
  condition:
    hash.sha256(0, filesize) == "49665430bea49701da165dbadd6b8f99bde4d804fcae784072d2460c3c7d5b1e"
}
```

### Sample 28: `4e92f1931a87c22e`

| Field | Value |
|---|---|
| SHA-256 | `4e92f1931a87c22e5544e6dae88a71ecdeb4e30251d71826df991fa3bbcf76f8` |
| Family label | `unknown` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-07-21 00:20:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b48d13e472c468a22b04cb63e685da67` |
| SHA-1 | `bf1962f1c31e4994ae1d0f58b41b2be1d78034d8` |
| SHA-256 | `4e92f1931a87c22e5544e6dae88a71ecdeb4e30251d71826df991fa3bbcf76f8` |
| SHA3-384 | `9348196944aba08eabaa9f4fd4293e1ef0df2598818453eec149f3606f567df4e4525b4c471a7c3868d1e76c667cf6ed` |
| TLSH | `T1243183C62B9756D43B7CAE11A98AC70C634C5ED864207BC8B5CFCCB16DC05D77D09A19` |
| SSDEEP | `24:ijCWCaNIdCEKECvvCgCEACACwlChCcgC2HR:CdO5B8rTAh/lwmnx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_4e92f193
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e92f1931a87c22e5544e6dae88a71ecdeb4e30251d71826df991fa3bbcf76f8"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-21 00:20:36"
  condition:
    hash.sha256(0, filesize) == "4e92f1931a87c22e5544e6dae88a71ecdeb4e30251d71826df991fa3bbcf76f8"
}
```

### Sample 29: `790788c47dd14f4f`

| Field | Value |
|---|---|
| SHA-256 | `790788c47dd14f4f25ab7befca04cdccf78b3071ac706f9ec3333e2faaebeeef` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.x86_64` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6497824583422cf1d6f524d614e918cd` |
| SHA-1 | `f02d6c5c070e58766ca19ffba4858b25a543be40` |
| SHA-256 | `790788c47dd14f4f25ab7befca04cdccf78b3071ac706f9ec3333e2faaebeeef` |
| SHA3-384 | `50729369bb03046c73846cb21322899d59d7e86daf67c7788e28cd4577904034603fd30facfc11e28caa1e3971394904` |
| TLSH | `T177832A02B9C085ECC189E138077F763AC425F1BD627AB2D73BD5BF1A2C19E501B1EA59` |
| TELFHASH | `t15911e13008cb3a9c01d74265734ffaf6d69705300988b470ea777e91ae6ff804e83955` |
| SSDEEP | `1536:ATNuOfMLWePYeNnVTbBub63gbyLa47Yj0ZOYhMsQEDdiqYRKROEMMgU:cHBePDNnlNub63gbyL/Y2hMs5DdiqdRq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_790788c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "790788c47dd14f4f25ab7befca04cdccf78b3071ac706f9ec3333e2faaebeeef"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.x86_64"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:34"
  condition:
    hash.sha256(0, filesize) == "790788c47dd14f4f25ab7befca04cdccf78b3071ac706f9ec3333e2faaebeeef"
}
```

### Sample 30: `b6391baa6d58d96c`

| Field | Value |
|---|---|
| SHA-256 | `b6391baa6d58d96c8a339e98a60371e646d6a558b50cecd8bf42047dc61127a0` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.mpsl` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0523a603386515626e6715e45a422a5f` |
| SHA-1 | `3b9682fa81440590ca942a6bd740ba506a5f9cf5` |
| SHA-256 | `b6391baa6d58d96c8a339e98a60371e646d6a558b50cecd8bf42047dc61127a0` |
| SHA3-384 | `7e1b4eaf199e1e17e5f9d4789e33c05aec44f84d299530d4da7ea2394ba8594f3799a4ef22eedf6b1183b72556aaebd5` |
| TLSH | `T19EB3910A7F600EF7EC9BDC374AAA1B4924DD241A25A87B75BD30D818F24B25F15E3874` |
| SSDEEP | `1536:VTUAnPWQ+tbHc2cAd88LZAJb7zEUX1p70wZsaD2A2j6Z3ktkprhu:1UAnPWQ+tbHc2FhNw1pYdj6jI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_b6391baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6391baa6d58d96c8a339e98a60371e646d6a558b50cecd8bf42047dc61127a0"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.mpsl"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:33"
  condition:
    hash.sha256(0, filesize) == "b6391baa6d58d96c8a339e98a60371e646d6a558b50cecd8bf42047dc61127a0"
}
```

### Sample 31: `7011eceba8cf057f`

| Field | Value |
|---|---|
| SHA-256 | `7011eceba8cf057f0103c1d44515be4211c1a56da468ac2ee3e0c12719c555b8` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.mips` |
| File type | `elf` |
| First seen | `2026-07-21 00:20:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17b2434e4236d50867f2074ac2a8cc28` |
| SHA-1 | `e232fa3662504aa60d19e6f5a7b6bb5779c94000` |
| SHA-256 | `7011eceba8cf057f0103c1d44515be4211c1a56da468ac2ee3e0c12719c555b8` |
| SHA3-384 | `7c8d103c83e4a5ab2f0d783979d0c38fd0b8d42f1c4ca80f0dcb8b45002ebb5ac7d7a14f3aa9b6a8288e9b99af19a4a9` |
| TLSH | `T1F8B3950E6E319F7DFBAC823857B78B119209379626E1D584D09CED025E7038E741FBA5` |
| TELFHASH | `t132018c08897813f083804cde6becff76e5a054df9a266e338d40e89a9b21a425e00c2c` |
| SSDEEP | `3072:er3x+xpNAsh+JySL/BjtfLdkPlx8eNEGwR:ex+xpCshOyS/LdkPlx8YwR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_7011eceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7011eceba8cf057f0103c1d44515be4211c1a56da468ac2ee3e0c12719c555b8"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.mips"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:32"
  condition:
    hash.sha256(0, filesize) == "7011eceba8cf057f0103c1d44515be4211c1a56da468ac2ee3e0c12719c555b8"
}
```

### Sample 32: `7694570bd0ddd16c`

| Field | Value |
|---|---|
| SHA-256 | `7694570bd0ddd16c6e60fbadd1d32a78c29944a1fa0cc19eacaa819d65654c05` |
| Family label | `Mirai` |
| File name | `nullnet.mpsl` |
| File type | `elf` |
| First seen | `2026-07-21 00:18:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c0db1eeb051d0e4d59bf713292112d6` |
| SHA-1 | `f0dea7628c77cdeebdecd1fbff7ba6d7890d2256` |
| SHA-256 | `7694570bd0ddd16c6e60fbadd1d32a78c29944a1fa0cc19eacaa819d65654c05` |
| SHA3-384 | `88a5dcabd3cabfa281a17edc26924d3a0f869992bc08485719c26e3289c1bc6fad3491e274174a2a0d1dd808ea872bda` |
| TLSH | `T1E9A3520B7F606EF7E82BDD3745F15B04248CB41621993B76BA34E958FA0A18F45E38B1` |
| SSDEEP | `1536:DhIvVaMEpKOHpisY27JkrbOsCU9rACpHyT2YAFZofQQp4x:AjMKOJisvdkrFCUNIAFz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_7694570b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7694570bd0ddd16c6e60fbadd1d32a78c29944a1fa0cc19eacaa819d65654c05"
    family = "Mirai"
    file_name = "nullnet.mpsl"
    file_type = "elf"
    first_seen = "2026-07-21 00:18:46"
  condition:
    hash.sha256(0, filesize) == "7694570bd0ddd16c6e60fbadd1d32a78c29944a1fa0cc19eacaa819d65654c05"
}
```

### Sample 33: `98c21848798bd325`

| Field | Value |
|---|---|
| SHA-256 | `98c21848798bd3259b4eefe0b455d510f6e481c476882f03708cefafdbb10e54` |
| Family label | `Mirai` |
| File name | `nullnet.spc` |
| File type | `elf` |
| First seen | `2026-07-21 00:18:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `921876e01ffcf338a8b993d8c4f05557` |
| SHA-1 | `6225acfcb5963c9a34c7e9dbeaa17e8828042d37` |
| SHA-256 | `98c21848798bd3259b4eefe0b455d510f6e481c476882f03708cefafdbb10e54` |
| SHA3-384 | `0234ed329de0414d95d426963b81757d3b91baa9aebf38c0925890e6692fd539b125edc8de681ea1ca367f03a76de293` |
| TLSH | `T1CA731A2679746E2BC4DD92FE12F38B24F1A62B0D28F4855D7D721D8EBF2059029137B2` |
| SSDEEP | `1536:Y1TO8X3EXi9/VyQtX4Z9BxmvAF9/joX55Fk5QGBHRYn:YxOwEMZX4pxmvRrSBHQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_98c21848
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98c21848798bd3259b4eefe0b455d510f6e481c476882f03708cefafdbb10e54"
    family = "Mirai"
    file_name = "nullnet.spc"
    file_type = "elf"
    first_seen = "2026-07-21 00:18:43"
  condition:
    hash.sha256(0, filesize) == "98c21848798bd3259b4eefe0b455d510f6e481c476882f03708cefafdbb10e54"
}
```

### Sample 34: `f9b929cf16581d82`

| Field | Value |
|---|---|
| SHA-256 | `f9b929cf16581d825fe88d676b5114e50d1b77daa4488d15ab0e3fd71bfb1796` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-07-21 00:18:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3aaff2095b760ca4d7b751bd41fa1ae0` |
| SHA-1 | `2c742ff117af70367a846f84da68adcac474c4ee` |
| SHA-256 | `f9b929cf16581d825fe88d676b5114e50d1b77daa4488d15ab0e3fd71bfb1796` |
| SHA3-384 | `3df94c340e2fe52e1b7c366b5ac898097df7a1a6a2db61d9ad9ac2231896a330d18c889b1c7f7a950257f0aef78fd3bf` |
| TLSH | `T1073112C52B9756D83B7CAE12A98A8B0D534C5ED8A4247B88B5CBCD725DC05C37C08A5B` |
| SSDEEP | `12:SAaZA+dAaZ6nRE+dAaZENNIlvHBA+dAaZtEK3H+dAaZRe+dAaZVHeq+dAaZ2N6Z4:wrGaNIpEKIvnEEkkwBtcE2xn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_f9b929cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9b929cf16581d825fe88d676b5114e50d1b77daa4488d15ab0e3fd71bfb1796"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-21 00:18:42"
  condition:
    hash.sha256(0, filesize) == "f9b929cf16581d825fe88d676b5114e50d1b77daa4488d15ab0e3fd71bfb1796"
}
```

### Sample 35: `df8048b1c8753f67`

| Field | Value |
|---|---|
| SHA-256 | `df8048b1c8753f67cb7eaf49032434fcda89b3a5fb581ba1b002efe9a66098b5` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-21 00:18:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e97ffdb502d141d6852b4789d175ff9` |
| SHA-1 | `c07b2c7c2246f85ddd2f636faf78eefc23c5b9f2` |
| SHA-256 | `df8048b1c8753f67cb7eaf49032434fcda89b3a5fb581ba1b002efe9a66098b5` |
| SHA3-384 | `19cc9b1e1f85c3fba215789c66b2445f3414395ec2272987752edff0eb548be6abfbbd3ae6c6a4acbc098290d0fb1858` |
| TLSH | `T116310FCA2BAB56D93B7CAE22F98AC70D63485DD8A5207B84F5DBCD705DC01C36C08676` |
| SSDEEP | `12:3J3LAaZAQLAaZ6nREQLAaZENNIlvHBAQLAaZtEK3HQLAaZReQLAaZVHeqQLAaZ2n:3J3RnMaNI5EK6vjWE22wB9cW2HR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_df8048b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df8048b1c8753f67cb7eaf49032434fcda89b3a5fb581ba1b002efe9a66098b5"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-21 00:18:41"
  condition:
    hash.sha256(0, filesize) == "df8048b1c8753f67cb7eaf49032434fcda89b3a5fb581ba1b002efe9a66098b5"
}
```

### Sample 36: `f7fc5c3daba8d328`

| Field | Value |
|---|---|
| SHA-256 | `f7fc5c3daba8d328b54ee98c69b1e28c78a7f3d7c25485db40f85b6fd49071b2` |
| Family label | `Mirai` |
| File name | `nullnet.ppc` |
| File type | `elf` |
| First seen | `2026-07-21 00:07:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c098d592658807f5d880fcbac9a9b49` |
| SHA-1 | `382b615aa3e18f7cc7c2c1d1a3c8a36062f378b5` |
| SHA-256 | `f7fc5c3daba8d328b54ee98c69b1e28c78a7f3d7c25485db40f85b6fd49071b2` |
| SHA3-384 | `17318d1d78c8f6187feeb1250ac1cae08fef09189d350715ca06a17212534dba281590e0d5ba4ee2a648683ee2f074e7` |
| TLSH | `T10C630902B7044F47E8A31DF0217B17E1D7EAFD9216A4F284720FBA9481B1DB37945E99` |
| SSDEEP | `1536:IEExhPfYX3oXaMlYCgDEGur3znHeQm6AXwte:rcHYzCgDbmDeQm6y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_f7fc5c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7fc5c3daba8d328b54ee98c69b1e28c78a7f3d7c25485db40f85b6fd49071b2"
    family = "Mirai"
    file_name = "nullnet.ppc"
    file_type = "elf"
    first_seen = "2026-07-21 00:07:46"
  condition:
    hash.sha256(0, filesize) == "f7fc5c3daba8d328b54ee98c69b1e28c78a7f3d7c25485db40f85b6fd49071b2"
}
```

### Sample 37: `001b17ec7703e99a`

| Field | Value |
|---|---|
| SHA-256 | `001b17ec7703e99a383799c633408b2315e9394bc1af1b924721af640b628a74` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-21 00:01:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6255259b59f9da0ab142cdceede5db80` |
| SHA-1 | `317c5fc375aa59f034af9b9b8da93fd156c70725` |
| SHA-256 | `001b17ec7703e99a383799c633408b2315e9394bc1af1b924721af640b628a74` |
| SHA3-384 | `90ddb40d7b29c2686a8f7fd926c32f18096453bb2f4851b4c06e78a9ceedf5c5129ca3d39b8e8a89904e66ade2d5cb6c` |
| TLSH | `T18104090AAF601EF7E86FCC3705E94B4A25DC655722A43BB53534E928F60A54F0AE3C74` |
| SSDEEP | `3072:hkmGeeedgvJVVU4EKZWGs0VZhH+SKzKUNMlSfnbL:+mQyKZWGs01L6HNtL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_001b17ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "001b17ec7703e99a383799c633408b2315e9394bc1af1b924721af640b628a74"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-21 00:01:55"
  condition:
    hash.sha256(0, filesize) == "001b17ec7703e99a383799c633408b2315e9394bc1af1b924721af640b628a74"
}
```

### Sample 38: `584bd68a9102cbaa`

| Field | Value |
|---|---|
| SHA-256 | `584bd68a9102cbaa179b916832ad5827c9e9d5b1af17f8570e54134c7a3db0d7` |
| Family label | `unknown` |
| File name | `nFedex_G68389B54.iso` |
| File type | `iso` |
| First seen | `2026-07-21 00:00:17` |
| Reporter | `fabiodemartin` |
| Tags | `iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0a9121f18db49f79524cac34f85a20c` |
| SHA-1 | `4bdc6fc196cb7dbb0e5f43e5b8e4ee3d585cdf81` |
| SHA-256 | `584bd68a9102cbaa179b916832ad5827c9e9d5b1af17f8570e54134c7a3db0d7` |
| SHA3-384 | `2db2f727f58f6796e0065fb11dbd4759c15d21c6f8334823454059722836413f8d1ac66eea8c99cea9de4d5baa38c4cc` |
| TLSH | `T17D551F4536C0E494CBD7DB7B3A1AA0E5F63A0CD962C40A6AF3A4FB54F5E0606F991730` |
| SSDEEP | `12288:hsGXUInZl5Zma47QVBP6zUCgdhSlNgm07qH+A+gOZ:3UIZl5ZmhQVBP6zULhSlXW1Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_584bd68a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "584bd68a9102cbaa179b916832ad5827c9e9d5b1af17f8570e54134c7a3db0d7"
    family = "unknown"
    file_name = "nFedex_G68389B54.iso"
    file_type = "iso"
    first_seen = "2026-07-21 00:00:17"
  condition:
    hash.sha256(0, filesize) == "584bd68a9102cbaa179b916832ad5827c9e9d5b1af17f8570e54134c7a3db0d7"
}
```

### Sample 39: `65c8a814d5439475`

| Field | Value |
|---|---|
| SHA-256 | `65c8a814d54394758ae4cff4318466c127117f46d22514a2ebb56610c8bf6dcd` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-20 23:59:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a41abe65af606f4e304cf45891b48862` |
| SHA-1 | `e3214cdb1f51f71a521a41baf3b07c3111f7f233` |
| SHA-256 | `65c8a814d54394758ae4cff4318466c127117f46d22514a2ebb56610c8bf6dcd` |
| SHA3-384 | `e3d191ffb097b9ff1777ea203e10eb0c50b92adc188fd79b6c24ca4596b34d90b36d7b7abba698b368a6e93a0be7dca9` |
| TLSH | `T1F5E3AFA89E0FBD93C2C6E3BE9E5A0FA7303734744614D1B70D00569DE6DEED588B2522` |
| SSDEEP | `3072:bDfdCg3++cVpPveAgN142M02fMqs9AG2vwz5IZsKhRcIA:bL0Q+j/dgN+2M0NqsZ2EIiKY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_65c8a814
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65c8a814d54394758ae4cff4318466c127117f46d22514a2ebb56610c8bf6dcd"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-20 23:59:54"
  condition:
    hash.sha256(0, filesize) == "65c8a814d54394758ae4cff4318466c127117f46d22514a2ebb56610c8bf6dcd"
}
```

### Sample 40: `e3950c8a20d06ad2`

| Field | Value |
|---|---|
| SHA-256 | `e3950c8a20d06ad26ea0b0b9662479bab92ff2459a92eccf80e9546b10da793a` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-07-20 23:53:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa7fe519d1900f92b47ac8ce8db0769a` |
| SHA-1 | `12c893fc5106919d4da767aa1b08dfee98ac0723` |
| SHA-256 | `e3950c8a20d06ad26ea0b0b9662479bab92ff2459a92eccf80e9546b10da793a` |
| SHA3-384 | `1718b185fe4b12ae62a538a9fe0b542d806572111069475cbde287d6f4a146c2b4f7c722200c79ec97750fcaba3dd48f` |
| TLSH | `T1BEA3C91E6E218FBDF769C33047B78E21A79833D626E1D685E26CD6011E6034E641FFA4` |
| TELFHASH | `t173217f5c4d7412e48b321d9e2baeff76e19030de0b326d378e11aaadba6d9425d00c1c` |
| SSDEEP | `1536:Gk8NZJjWAaRmkGMvAbNVF1F5pzePQvl9Leq8kwmlas/wdo:CZJjBaRmvBwPyl9Zluo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_e3950c8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3950c8a20d06ad26ea0b0b9662479bab92ff2459a92eccf80e9546b10da793a"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-20 23:53:44"
  condition:
    hash.sha256(0, filesize) == "e3950c8a20d06ad26ea0b0b9662479bab92ff2459a92eccf80e9546b10da793a"
}
```

### Sample 41: `a5892c7527aceab6`

| Field | Value |
|---|---|
| SHA-256 | `a5892c7527aceab6f01efb2e266fce135dc6701e3d34cb5f56b857bb28aed901` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-07-20 23:52:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab8a3b09e6878b2ffe3d13cee8443b12` |
| SHA-1 | `dbb2a0df710089474dea7ecec4e0479f578988c7` |
| SHA-256 | `a5892c7527aceab6f01efb2e266fce135dc6701e3d34cb5f56b857bb28aed901` |
| SHA3-384 | `03dc91ab33779476156dc42c498ce2b57505877c6a9c0c83974dfb7b0eb7d4d3d9d896906e69149eac7cf9e34707f8e1` |
| TLSH | `T1D9F2F23A220382A7E549C17F0EFF43403EE51677A8429CC6D40EEE668EDD572744AED9` |
| SSDEEP | `768:oQAYWYARxmy9oL05yz63x5qWuqzi4efsQaCfFJgGlzDpbuR1JV:1V5AHvqLGyz63Tq/qzihvPf/VJuP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_a5892c75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5892c7527aceab6f01efb2e266fce135dc6701e3d34cb5f56b857bb28aed901"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-20 23:52:30"
  condition:
    hash.sha256(0, filesize) == "a5892c7527aceab6f01efb2e266fce135dc6701e3d34cb5f56b857bb28aed901"
}
```

### Sample 42: `f42cd03d9db9469b`

| Field | Value |
|---|---|
| SHA-256 | `f42cd03d9db9469b3cc83f8a3ef36a9e72211fb6b481456b1e199563a523dc87` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 23:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b13e4898c4e966997b6ba6f435a38b21` |
| SHA-1 | `cd590dd5f717eee538fc31ddec189a02e8713a3d` |
| SHA-256 | `f42cd03d9db9469b3cc83f8a3ef36a9e72211fb6b481456b1e199563a523dc87` |
| SHA3-384 | `855f9fd2c691f3c02b724e7f096a6ccbfb458bab01ce7a7cfcdf987ceb9fa365890481744b88c9e9d7aa5e602408ceb6` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D8E63394AAE015ECD2BB90BDBEE18951D554B4BB0F73CAEF03AC43651C270B1493E663` |
| SSDEEP | `393216:iSeJ/d4XnsRIYETZ6dp19pBitO0JXMCHWUjX4cuI3/PGTAI:iSs4XAIY40dp19pBitrXMb8XNH/O7` |
| ICON-DHASH | `71f0e8e8e8e8f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_f42cd03d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42cd03d9db9469b3cc83f8a3ef36a9e72211fb6b481456b1e199563a523dc87"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 23:52:09"
  condition:
    hash.sha256(0, filesize) == "f42cd03d9db9469b3cc83f8a3ef36a9e72211fb6b481456b1e199563a523dc87"
}
```

### Sample 43: `cd4498d39e8126c9`

| Field | Value |
|---|---|
| SHA-256 | `cd4498d39e8126c9779a7d55fc860b8e06d1875d8f6add1ed208698c00c03811` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-20 23:43:47` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX10.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10c48851ed02d156cf1b0053f3c660ed` |
| SHA-1 | `b72153e4ab81abb2ec13de8e9198e7f73f814674` |
| SHA-256 | `cd4498d39e8126c9779a7d55fc860b8e06d1875d8f6add1ed208698c00c03811` |
| SHA3-384 | `61115d427b69ab14d9d5287af099ca87c9d63ed48d95fceb111292c6ce8ca66e070ceb15497045b4f088a47834a84b1f` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T130E60133B28A653EE06E1B365A72A150553B6E616D128D1ADEF018ACCF3D1703E3F746` |
| SSDEEP | `98304:ooJJq4BhOFzR0lZj7RWD9DYGKI0MR5vK1N:DhOY7je0QK1` |
| ICON-DHASH | `b268ccdccc33aad0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_cd4498d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4498d39e8126c9779a7d55fc860b8e06d1875d8f6add1ed208698c00c03811"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 23:43:47"
  condition:
    hash.sha256(0, filesize) == "cd4498d39e8126c9779a7d55fc860b8e06d1875d8f6add1ed208698c00c03811"
}
```

### Sample 44: `8c70ae6d0965351e`

| Field | Value |
|---|---|
| SHA-256 | `8c70ae6d0965351ec8417ed37bba85dd58b05afae292cf932efeb4fcc5c7b331` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 22:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ab739aea74c61a27a85c7e5c05abf52` |
| SHA-1 | `971147e924e096e95ed563eff41288a9fcc348cb` |
| SHA-256 | `8c70ae6d0965351ec8417ed37bba85dd58b05afae292cf932efeb4fcc5c7b331` |
| SHA3-384 | `537968035d32c431146209f0af77059bb29991acff4b98c62e434b4de603d3337c85d4d99aebc86222c2c5971196f6fd` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T164E63314AAE101CFF6A3503DDDE30695F99A3CBB0771808F96E457726E672E2C839607` |
| SSDEEP | `393216:bVGw47wd0g6UywFr5QYUxXMCHWUjX4cuI3/PGTAI:bVnd0PBs6YOXMb8XNH/O7` |
| ICON-DHASH | `70f0f0e8e8e0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_8c70ae6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c70ae6d0965351ec8417ed37bba85dd58b05afae292cf932efeb4fcc5c7b331"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 22:52:09"
  condition:
    hash.sha256(0, filesize) == "8c70ae6d0965351ec8417ed37bba85dd58b05afae292cf932efeb4fcc5c7b331"
}
```

### Sample 45: `6aae69fdd57ce162`

| Field | Value |
|---|---|
| SHA-256 | `6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099` |
| Family label | `Prometei` |
| File name | `6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099` |
| File type | `elf` |
| First seen | `2026-07-20 22:48:04` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10dce2eecd69f7802f240a18d65fb09e` |
| SHA-1 | `5b3a0bff74de208714a3f233f47bbbf4f6c099f7` |
| SHA-256 | `6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099` |
| SHA3-384 | `8ee8b97c12f8b1b81342c8493b6dc479554d48006d9f665309732318c75815a28f94d4daddcd095b7713f58d3b7e074e` |
| TLSH | `T111A423B4F9219E9F6DD769B91B24831DE182C172589D4C2313AE94E34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdY:Fs6pyCC/Ya2hpi6T6N46` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_045_6aae69fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099"
    family = "Prometei"
    file_name = "6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099"
    file_type = "elf"
    first_seen = "2026-07-20 22:48:04"
  condition:
    hash.sha256(0, filesize) == "6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099"
}
```

### Sample 46: `bca78e472cdf94c1`

| Field | Value |
|---|---|
| SHA-256 | `bca78e472cdf94c16fd67cdf2894d7286c17b370007878b988b9a9f9705f99d5` |
| Family label | `unknown` |
| File name | `yuanbao.exe` |
| File type | `exe` |
| First seen | `2026-07-20 22:38:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1972777ad8a8b590091efd3a4dde67b` |
| SHA-1 | `33513fec5b369256cab40980e022ff3368089c0e` |
| SHA-256 | `bca78e472cdf94c16fd67cdf2894d7286c17b370007878b988b9a9f9705f99d5` |
| SHA3-384 | `fb4064d768202c9e7c6d60414bd82200cd0cc8a9a415453aea9571e2f1c900e480c51f0fb3c54747c863ec3f658c894d` |
| IMPHASH | `311d1e93d89e02a2908fe4b6d6a25ef7` |
| TLSH | `T1F437338430E1D4BEC11029B953EDD9B3AE35EDE4CB0795FB33C4FD0B61B09986A6125A` |
| SSDEEP | `393216:siGrZag/6KiuKk9k9B/yyq03lvGwODuycrJSFuRMYp/27bWPRz9Ftjh1:dGrZl/UBky9B/yy1VLgpop2ihtjh1` |
| ICON-DHASH | `cc0e274545330ecc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_bca78e47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca78e472cdf94c16fd67cdf2894d7286c17b370007878b988b9a9f9705f99d5"
    family = "unknown"
    file_name = "yuanbao.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:38:46"
  condition:
    hash.sha256(0, filesize) == "bca78e472cdf94c16fd67cdf2894d7286c17b370007878b988b9a9f9705f99d5"
}
```

### Sample 47: `96c0911c225219cf`

| Field | Value |
|---|---|
| SHA-256 | `96c0911c225219cfd380076f5196d7ee87c617cddb968d3d465122473e20d6fb` |
| Family label | `Gh0stRAT` |
| File name | `yuanbao.exe` |
| File type | `exe` |
| First seen | `2026-07-20 22:38:00` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0stRAT, SilverFox, upx, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2017e80c1b53a7358978680428d45b98` |
| SHA-1 | `b56dd3281663e2db6f69991ef2f9c3c90ef21d71` |
| SHA-256 | `96c0911c225219cfd380076f5196d7ee87c617cddb968d3d465122473e20d6fb` |
| SHA3-384 | `f9a07dffd67e5a06aec625bde71a2d67b1c176f4ea68d3223aaf58e74a0ae63d242343764a9f49d0c5d4269614fbf8f5` |
| IMPHASH | `b484b52df60e8d823b647a09bb1e39f9` |
| TLSH | `T1483733842075E4BEC2541AFA92EDD9B36E356D24CB47E4DF12C5FC0FA0F0A8C5AA1752` |
| SSDEEP | `393216:TGrZag/6KiuKk9k9B/yyq03lvGwODuycrJSFuRMYp/27bWPRz9Ftjh1:TGrZl/UBky9B/yy1VLgpop2ihtjh1` |
| ICON-DHASH | `cc0e274545330ecc` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_047_96c0911c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96c0911c225219cfd380076f5196d7ee87c617cddb968d3d465122473e20d6fb"
    family = "Gh0stRAT"
    file_name = "yuanbao.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:38:00"
  condition:
    hash.sha256(0, filesize) == "96c0911c225219cfd380076f5196d7ee87c617cddb968d3d465122473e20d6fb"
}
```

### Sample 48: `63522452b1ed07e4`

| Field | Value |
|---|---|
| SHA-256 | `63522452b1ed07e4f33376b0b8c85a4045e85594c3e7b03354afd985b691522f` |
| Family label | `ValleyRAT` |
| File name | `2026.07.20裁员名单及补偿方案_SUET.exe` |
| File type | `exe` |
| First seen | `2026-07-20 22:37:02` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bg[qtsc], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96aacf012c439b535c3ea2b689bfa667` |
| SHA-1 | `179bbc5875d95901a512995f461a234524285e3f` |
| SHA-256 | `63522452b1ed07e4f33376b0b8c85a4045e85594c3e7b03354afd985b691522f` |
| SHA3-384 | `25366ca7639f62972c37148beba1c4321c5e5221b2bc29b9d3ec85c0f54280360c252f2f7a3764618ba24ea8ca6859a4` |
| IMPHASH | `a8ccd30aac69e6061dedcb19d3b311df` |
| TLSH | `T1249533BE8E2E57DAC5AEC9F0F535D2D6A9002444A4B697C637C0079D67230B0ECE72D9` |
| SSDEEP | `24576:7IO57nnTvIOfOQ+M3WAvbdlUywk9UG8amWJ0+/1m7S:HFbIOmQTHU89UG8aJ+S` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_048_63522452
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63522452b1ed07e4f33376b0b8c85a4045e85594c3e7b03354afd985b691522f"
    family = "ValleyRAT"
    file_name = "2026.07.20裁员名单及补偿方案_SUET.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:37:02"
  condition:
    hash.sha256(0, filesize) == "63522452b1ed07e4f33376b0b8c85a4045e85594c3e7b03354afd985b691522f"
}
```

### Sample 49: `d96fc5f700b931e4`

| Field | Value |
|---|---|
| SHA-256 | `d96fc5f700b931e47dee0b979f267ac803f02a6726a4cb6464daf7dd17bc17fe` |
| Family label | `NanoCore` |
| File name | `4357b7160b0765b1714a08aeb54c2dc8.exe` |
| File type | `exe` |
| First seen | `2026-07-20 22:30:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4357b7160b0765b1714a08aeb54c2dc8` |
| SHA-1 | `e2b2fbef3bd3eb79866be82629fb802542342120` |
| SHA-256 | `d96fc5f700b931e47dee0b979f267ac803f02a6726a4cb6464daf7dd17bc17fe` |
| SHA3-384 | `ad6a1908414411af48a06803147866ddca543fd2cc4ba014a0f619e831393e5904e4bedde435883bf6730583c8cfca90` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11314CF267BF98A2FE2DE86B9611212028379C2E399C3F3DE18D455B35F267E506071D3` |
| SSDEEP | `3072:MzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HINDP+1Nda82N+xdkv9iRLGeQLX:MLV6Bta6dtJmakIM54kAgNpq` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_049_d96fc5f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96fc5f700b931e47dee0b979f267ac803f02a6726a4cb6464daf7dd17bc17fe"
    family = "NanoCore"
    file_name = "4357b7160b0765b1714a08aeb54c2dc8.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:30:05"
  condition:
    hash.sha256(0, filesize) == "d96fc5f700b931e47dee0b979f267ac803f02a6726a4cb6464daf7dd17bc17fe"
}
```

### Sample 50: `0e1ca1c207eba5bc`

| Field | Value |
|---|---|
| SHA-256 | `0e1ca1c207eba5bc7b8fb7fb14698999fe9e4189d56ca5b88f86dacfbf409ddb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-20 22:19:52` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c057c2ba117f199df9f9f90e8caeae5d` |
| SHA-1 | `c3ac736ebe013619980c44f5690f3723534212a5` |
| SHA-256 | `0e1ca1c207eba5bc7b8fb7fb14698999fe9e4189d56ca5b88f86dacfbf409ddb` |
| SHA3-384 | `d8668ff7ebc9d10aed75c709f80bfe6d96518fedc06c13282bc05e0f484a7138cf87046f3f5b85a41d4a147dcd4fec55` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T19C825A0FB9424726C5E11074A275877BDAB9A8B2338814DBF7D089A90B782D1FC3315F` |
| SSDEEP | `384:+IqQVVaFYhKUygZu94gNTcNQav8U9c2KF:8pUyV9da0UF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_0e1ca1c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e1ca1c207eba5bc7b8fb7fb14698999fe9e4189d56ca5b88f86dacfbf409ddb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 22:19:52"
  condition:
    hash.sha256(0, filesize) == "0e1ca1c207eba5bc7b8fb7fb14698999fe9e4189d56ca5b88f86dacfbf409ddb"
}
```

### Sample 51: `6a25ea3dc7e86e1d`

| Field | Value |
|---|---|
| SHA-256 | `6a25ea3dc7e86e1d0bdcf0becbfb120b4d2b36c38cb63e5106ee7e8ddea1cf7c` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 21:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27b6bbc0fe5ae39d0461171bd3e0ed94` |
| SHA-1 | `c9d7b16ab3b79e33495459c27c3eaa95d4b08a09` |
| SHA-256 | `6a25ea3dc7e86e1d0bdcf0becbfb120b4d2b36c38cb63e5106ee7e8ddea1cf7c` |
| SHA3-384 | `26f9f3a1caab5219353256526c7639344529a604d3e2f97ceccd47e17297b306c93474b8665062b78380828b662b11a1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T14BE6330C66E516EAEB63813DDFF36286E564B8610B73C6DF5B5483B4AD832E1093C613` |
| SSDEEP | `393216:sSmrvjlmcGaMbXuT1MvuXMCHWUjXScuI3/PGTAI:s9N5qXuT1MvuXMb8XvH/O7` |
| ICON-DHASH | `5471f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_6a25ea3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a25ea3dc7e86e1d0bdcf0becbfb120b4d2b36c38cb63e5106ee7e8ddea1cf7c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 21:52:11"
  condition:
    hash.sha256(0, filesize) == "6a25ea3dc7e86e1d0bdcf0becbfb120b4d2b36c38cb63e5106ee7e8ddea1cf7c"
}
```

### Sample 52: `b66775e5a6169599`

| Field | Value |
|---|---|
| SHA-256 | `b66775e5a6169599519e5b3e035bea6ca2824e14ad59662b9d43d356ba6b3c4d` |
| Family label | `RemusStealer` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-07-20 21:52:07` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7ee082acfd43a938bb8aa0a5f65e610` |
| SHA-1 | `317683b99cef6340234e0e65c3be9b1a96ac020a` |
| SHA-256 | `b66775e5a6169599519e5b3e035bea6ca2824e14ad59662b9d43d356ba6b3c4d` |
| SHA3-384 | `c325142949ff2c820a7897c4d4aff6ccc0ce355a71808f36b5c984a6b26ed1d71996d61fe3a4afd1cd787ebd2ad6dc68` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18F75192C27F969A8F1B77F358AF56145DB3BBB72A93BD64E0600420F1532A018D52F36` |
| SSDEEP | `24576:PKCKoguYjLBgWT1Jy+RZfjEERR/4OhUrDNQDT/eNKS8gw3gWYvmMBjq:sSWDy+RZfLfhWDNoT/eNKBgQpYuy` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_052_b66775e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66775e5a6169599519e5b3e035bea6ca2824e14ad59662b9d43d356ba6b3c4d"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-20 21:52:07"
  condition:
    hash.sha256(0, filesize) == "b66775e5a6169599519e5b3e035bea6ca2824e14ad59662b9d43d356ba6b3c4d"
}
```

### Sample 53: `e1f122c6154e1ec4`

| Field | Value |
|---|---|
| SHA-256 | `e1f122c6154e1ec48b09f423d59b2f007751bb70f83fb37967d8263526045358` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-20 21:40:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dfa5975722cad801460d770cea685ca` |
| SHA-1 | `de6b9d9790a493b3d69f694281fd368ce8e73931` |
| SHA-256 | `e1f122c6154e1ec48b09f423d59b2f007751bb70f83fb37967d8263526045358` |
| SHA3-384 | `eda4c0a921a1bdbd17405ad22cce1e8dfebad6692d64c7a2dcdf4a4eb38b323aecc2203f58b69b92586ab4c2f4141dbb` |
| TLSH | `T1E9235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A6ADD109B1D` |
| SSDEEP | `768:++39GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:++Acr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_e1f122c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1f122c6154e1ec48b09f423d59b2f007751bb70f83fb37967d8263526045358"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 21:40:32"
  condition:
    hash.sha256(0, filesize) == "e1f122c6154e1ec48b09f423d59b2f007751bb70f83fb37967d8263526045358"
}
```

### Sample 54: `1551ea450f0da4f6`

| Field | Value |
|---|---|
| SHA-256 | `1551ea450f0da4f6e6494b4fab62a7637f7ec5d1b7d6d47b032314ab5e761717` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-20 20:56:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3145cfdcfb520b12abe7a8ab9892a26` |
| SHA-1 | `d7a1fa26361f42e7f35827d48b03820103eb4203` |
| SHA-256 | `1551ea450f0da4f6e6494b4fab62a7637f7ec5d1b7d6d47b032314ab5e761717` |
| SHA3-384 | `13f0e5b75ccca796721c20bbee8c848fc067dc70593b8a1e8b6e5a03ee23e76c28f55c0129c5227657eb915a25498a6d` |
| TLSH | `T16B236C6516857C14AA98C4375C7E2F0CBDAD43E6314492EE7FCE3CF28C4A6AD9208B1D` |
| SSDEEP | `768:Vgq9NyXsZztCQ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:qqHusZ4cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_1551ea45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1551ea450f0da4f6e6494b4fab62a7637f7ec5d1b7d6d47b032314ab5e761717"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 20:56:41"
  condition:
    hash.sha256(0, filesize) == "1551ea450f0da4f6e6494b4fab62a7637f7ec5d1b7d6d47b032314ab5e761717"
}
```

### Sample 55: `53b2d24c9aefe01a`

| Field | Value |
|---|---|
| SHA-256 | `53b2d24c9aefe01a768f6e2c637ab9fd56dcede852925cec18eccae58dfecec7` |
| Family label | `unknown` |
| File name | `YZi Labs - Audit Confirmation Form - June 30 2026.docx.scpt` |
| File type | `unknown` |
| First seen | `2026-07-20 20:54:39` |
| Reporter | `smica83` |
| Tags | `DPRK` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c56a75870a47a01374c6a2884c8d643` |
| SHA-256 | `53b2d24c9aefe01a768f6e2c637ab9fd56dcede852925cec18eccae58dfecec7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_53b2d24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53b2d24c9aefe01a768f6e2c637ab9fd56dcede852925cec18eccae58dfecec7"
    family = "unknown"
    file_name = "YZi Labs - Audit Confirmation Form - June 30 2026.docx.scpt"
    file_type = "unknown"
    first_seen = "2026-07-20 20:54:39"
  condition:
    hash.sha256(0, filesize) == "53b2d24c9aefe01a768f6e2c637ab9fd56dcede852925cec18eccae58dfecec7"
}
```

### Sample 56: `7391ec43b2e0621c`

| Field | Value |
|---|---|
| SHA-256 | `7391ec43b2e0621c8c6472b686b900722a4f22ca037b3ebd0ade5a86a880332b` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 20:52:24` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a34a543870f0c463c4bd83fb37883d83` |
| SHA-1 | `ef5fee2f2ddf7a7bd246a0671cbc08a0083f6ea1` |
| SHA-256 | `7391ec43b2e0621c8c6472b686b900722a4f22ca037b3ebd0ade5a86a880332b` |
| SHA3-384 | `e57d126d763e37039f2ebb9580d26229825bc8b4ff39fff3f48a1958efe4428866ea9dd359a0f59744e5622f50401451` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C0E633589DE001FAFDB34138EED2A65565B5B8750332C6EF07984BA28E672E04D3E743` |
| SSDEEP | `393216:g+dc3JDVvdbBL67hZb/1IPpXMCHWUjXzcuI3/PGTAI:gVZPI3+PpXMb8XwH/O7` |
| ICON-DHASH | `71d89ea29ac6e471` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_7391ec43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7391ec43b2e0621c8c6472b686b900722a4f22ca037b3ebd0ade5a86a880332b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 20:52:24"
  condition:
    hash.sha256(0, filesize) == "7391ec43b2e0621c8c6472b686b900722a4f22ca037b3ebd0ade5a86a880332b"
}
```

### Sample 57: `f2796171d5145438`

| Field | Value |
|---|---|
| SHA-256 | `f2796171d51454389ccb9d26a65794a030b1aaa80dbcb79a99153443c3151e40` |
| Family label | `RemusStealer` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-07-20 20:52:07` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dde34c83191460a74b0e6cd489ea6d4e` |
| SHA-1 | `7edc5c6f7a2b5c0b30cda37109a462da536e1c29` |
| SHA-256 | `f2796171d51454389ccb9d26a65794a030b1aaa80dbcb79a99153443c3151e40` |
| SHA3-384 | `493aa6433cbfc068aa4a13de1478565dd28512c270f7f11c18905dd50e6b9640a284ff5ccd3154412d3bf6b261a9edfd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10E75292C27F969A8F1B77F358AF56145DB3BBB72A93BD64E0600820F1531A018D52F36` |
| SSDEEP | `24576:4novWxDuBgWT1Jy+RZfjEERR/4OhUrDN59sW929AzmtjvmMBjh:KXWDy+RZfLfhWDNkW9qFtjuy` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_057_f2796171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2796171d51454389ccb9d26a65794a030b1aaa80dbcb79a99153443c3151e40"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-20 20:52:07"
  condition:
    hash.sha256(0, filesize) == "f2796171d51454389ccb9d26a65794a030b1aaa80dbcb79a99153443c3151e40"
}
```

### Sample 58: `a927fe3149e454d0`

| Field | Value |
|---|---|
| SHA-256 | `a927fe3149e454d08a3a87131ced2a785da121fa879566dbb274aa29d7732eb6` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-20 20:49:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51d086123dc2ae69563a429737109239` |
| SHA-1 | `8443c0c133da96836bc84f8de527e4af6e834a50` |
| SHA-256 | `a927fe3149e454d08a3a87131ced2a785da121fa879566dbb274aa29d7732eb6` |
| SHA3-384 | `056a88e00614c6286abe45ae26af97337311ef290984617287cfd41fd753ac79d50d26807be66e084006e990a915a4d9` |
| TLSH | `T1CEC329A9F890DE52C6D526B6FB4E418C33231778C3DE7106CE149E3467FB95A0A3E942` |
| SSDEEP | `3072:QuIBvPRfsNDUxMa3tIDrcYEEUIAyMW0NwhBigpmqzWNiF+WOuS5mf1Dl:QJ5GytercYEEUIAyMWGwiOmqzpJom95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_a927fe31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a927fe3149e454d08a3a87131ced2a785da121fa879566dbb274aa29d7732eb6"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 20:49:36"
  condition:
    hash.sha256(0, filesize) == "a927fe3149e454d08a3a87131ced2a785da121fa879566dbb274aa29d7732eb6"
}
```

### Sample 59: `c67577c4771d1228`

| Field | Value |
|---|---|
| SHA-256 | `c67577c4771d12285ea8fdca4dc7700f75861f8f74f82f8126c49e86a4b40044` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-20 20:48:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c206a21430cfb38bdaf2cf88cf436d8c` |
| SHA-1 | `368ef35693f3fe62f4112181d1c7ccfeaf74948a` |
| SHA-256 | `c67577c4771d12285ea8fdca4dc7700f75861f8f74f82f8126c49e86a4b40044` |
| SHA3-384 | `68e839da51bfc0c6dc5f0267a43a437cf46c4639872195cd533792e22c029e0384e74e3bfe470744c9ed5346aab532e7` |
| TLSH | `T1904302F5364C5475C48A0DF028BD5042B34BABDEE9FA25B020BDDAB0BB71197386C965` |
| SSDEEP | `1536:YQxgxPJhfVIz2FzQOQRgD3jEShEFENC6+HlEvffF:Txg1JhdIzOQ1RgD34ShcSCmd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_c67577c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c67577c4771d12285ea8fdca4dc7700f75861f8f74f82f8126c49e86a4b40044"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 20:48:39"
  condition:
    hash.sha256(0, filesize) == "c67577c4771d12285ea8fdca4dc7700f75861f8f74f82f8126c49e86a4b40044"
}
```

### Sample 60: `0934db4eb30297c9`

| Field | Value |
|---|---|
| SHA-256 | `0934db4eb30297c9815b0eefed038850d56b721cca115fc6881f4b870df41753` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-20 20:42:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d89ff7f54073cd31a6c6ad15b1326d7` |
| SHA-1 | `ae3b5f9c6e427fcd5c3e3dcccc08ceaa039a694c` |
| SHA-256 | `0934db4eb30297c9815b0eefed038850d56b721cca115fc6881f4b870df41753` |
| SHA3-384 | `fde3527631e3794faca5b6936aa9e8597a2b0a0dc9783b084a46fb1e38f308f9022fb775ad151f4305bc57507e3f58f1` |
| TLSH | `T10FC27D956A967C44BEC98A3E4CBD2B0D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:C8vCB+25j6es8R59FYpMSUpi+20qUpi+20YQX:C8l25Jfd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_0934db4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0934db4eb30297c9815b0eefed038850d56b721cca115fc6881f4b870df41753"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-20 20:42:34"
  condition:
    hash.sha256(0, filesize) == "0934db4eb30297c9815b0eefed038850d56b721cca115fc6881f4b870df41753"
}
```

### Sample 61: `40df91b940eea28d`

| Field | Value |
|---|---|
| SHA-256 | `40df91b940eea28d176edccda20a8e2e4e281eb531254486d4c69af08dd29842` |
| Family label | `Mirai` |
| File name | `morte.arm7` |
| File type | `elf` |
| First seen | `2026-07-20 20:39:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d4b0dba09b8f4ca7f97f559a28f3c56` |
| SHA-1 | `c102181fc2f978a2b5a31c0c33c24c2659b743f4` |
| SHA-256 | `40df91b940eea28d176edccda20a8e2e4e281eb531254486d4c69af08dd29842` |
| SHA3-384 | `791b7b0a9922f6ecc194ffe77f664d3824ac4bbc7815ac8697d339a96943a002119a67994c5fa4f3e831b5d277b81f9a` |
| TLSH | `T1B6144B46EA418A23C0D7177AB6AF414A3333A7A4D3DB730699286FB43BC675F0E63505` |
| TELFHASH | `t1f1312fb1833652186a61cb9c99ecb7b5012cc7031246ff33ef3684ac041944ee53ac0f` |
| SSDEEP | `6144:bzwCD8W1DCPyalbRblciQsYCKDcerNrye3NwM/9YjGC+:bzwCD8WBCPyalbRblciQD/JByWJ/6je` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_40df91b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40df91b940eea28d176edccda20a8e2e4e281eb531254486d4c69af08dd29842"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 20:39:35"
  condition:
    hash.sha256(0, filesize) == "40df91b940eea28d176edccda20a8e2e4e281eb531254486d4c69af08dd29842"
}
```

### Sample 62: `90ac8ec4e015343f`

| Field | Value |
|---|---|
| SHA-256 | `90ac8ec4e015343f2f175d29a2e147109a76fd65582dfa9cad80144826336872` |
| Family label | `Mirai` |
| File name | `morte.arm6` |
| File type | `elf` |
| First seen | `2026-07-20 20:39:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `127b7061274ffbcabdf1f8b93390749b` |
| SHA-1 | `66e20ddf178ec289f28396b575f12a53d7c17612` |
| SHA-256 | `90ac8ec4e015343f2f175d29a2e147109a76fd65582dfa9cad80144826336872` |
| SHA3-384 | `04d713fbf230c4b94f62068292f3586d067ceec1a35a14a702f729dcaa6b271b1b34be07e10c6e40cb7b804264913cab` |
| TLSH | `T134C32986F8824B22D6D712BEF92D118E331317B8E3DE32229E245F2177C652B0E77955` |
| TELFHASH | `t1bde0c69f66352a6a2cdc8000879f7a06dbec3a9f2b0528c6c33d4a0e6043dc2340c01e` |
| SSDEEP | `3072:GIQpxQEjVJ3QkkjmG7L6apVH9dhd2P3x9i:GIyxQgVJ3QkY57Gandd2Z9i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_90ac8ec4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90ac8ec4e015343f2f175d29a2e147109a76fd65582dfa9cad80144826336872"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 20:39:32"
  condition:
    hash.sha256(0, filesize) == "90ac8ec4e015343f2f175d29a2e147109a76fd65582dfa9cad80144826336872"
}
```

### Sample 63: `3f509b8445f1b263`

| Field | Value |
|---|---|
| SHA-256 | `3f509b8445f1b263397f3d531f478aeb9b046e0ab7582549a622e912a7161fda` |
| Family label | `Mirai` |
| File name | `morte.arm7` |
| File type | `elf` |
| First seen | `2026-07-20 20:38:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1de1a8bdd8806f731beef46446e05388` |
| SHA-1 | `6744313410664c9f4be860f4dabf9485f478ffdc` |
| SHA-256 | `3f509b8445f1b263397f3d531f478aeb9b046e0ab7582549a622e912a7161fda` |
| SHA3-384 | `1c8ec8c93fc97a877126ceb120bad93b74ef69dbadfebbde7a9b7aa86799f7257a8a1ad647ca73aec0f281c240f99515` |
| TLSH | `T17A6302B49055CD93CA3C48B09E3E0FA77D494AB8646678FE56704B586A43FC8ABF4CC1` |
| SSDEEP | `1536:M6km9VKx73LQuBsOahcEFMGprfaY+Ljf2dX08T6bKhVmse0x:M6XA3TsOalTcLje28DVTr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_3f509b84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f509b8445f1b263397f3d531f478aeb9b046e0ab7582549a622e912a7161fda"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 20:38:37"
  condition:
    hash.sha256(0, filesize) == "3f509b8445f1b263397f3d531f478aeb9b046e0ab7582549a622e912a7161fda"
}
```

### Sample 64: `9354ba8758ad0702`

| Field | Value |
|---|---|
| SHA-256 | `9354ba8758ad0702251b2ea6dfa82cb7ba34c0e7f32e5cfc83aed0baebb3c456` |
| Family label | `Mirai` |
| File name | `morte.arm6` |
| File type | `elf` |
| First seen | `2026-07-20 20:38:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e830cc6cf92df7c2319f47398da46d1` |
| SHA-1 | `89f489384019796d36a746028599cef14af410aa` |
| SHA-256 | `9354ba8758ad0702251b2ea6dfa82cb7ba34c0e7f32e5cfc83aed0baebb3c456` |
| SHA3-384 | `688a5e66cf254d1a7e47805c2977fdf64ec3c2d550f0a6cad681eec9e626b88c3df482695770652cb77da0dd2d7fb64c` |
| TLSH | `T18223F20D01199D28EDD0F8379A58D489523B4FD9EABCFC1B7590E4647EA53C2E3BE181` |
| SSDEEP | `1536:lOWfAAherYCyhib3sdTzOQGObIm2CRuzddJlj0qyDL2d6b5Ly:SAMrshocdHOQGPm2CgRdJq9Q6b5Ly` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_9354ba87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9354ba8758ad0702251b2ea6dfa82cb7ba34c0e7f32e5cfc83aed0baebb3c456"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 20:38:36"
  condition:
    hash.sha256(0, filesize) == "9354ba8758ad0702251b2ea6dfa82cb7ba34c0e7f32e5cfc83aed0baebb3c456"
}
```

### Sample 65: `b6819af7882a880a`

| Field | Value |
|---|---|
| SHA-256 | `b6819af7882a880ab0119b79fa068177570e53cf205653e4091bdfafc7ccf8b8` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-07-20 20:28:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dd79bd1a6db847df30fd656f2b06dab` |
| SHA-1 | `a739d9c7bae3078623945a2861d9100accb0ef1a` |
| SHA-256 | `b6819af7882a880ab0119b79fa068177570e53cf205653e4091bdfafc7ccf8b8` |
| SHA3-384 | `3c852a6088cc1dcccad6e46567ff973fbbf5814f51e90115448a70ed5132531e2e4b9a5e4fbe12e9c57d2c41473c1884` |
| TLSH | `T122C37DC5B50D7EAEE4D32D7CC20A17176E1C9E519C83410190B5FE031ABB6E72E26AC7` |
| TELFHASH | `t18ad0b1f1878fa601458cdbcd83ca775c4a0dd141004bef43fd22553c80a591cb91998f` |
| SSDEEP | `3072:129lr4s2FCP0ISEHZ6USxMPWFRSRvtWRhSQLLjyoWBp:129QFs0INxSmPuEvtWfSQXvI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_b6819af7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6819af7882a880ab0119b79fa068177570e53cf205653e4091bdfafc7ccf8b8"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 20:28:46"
  condition:
    hash.sha256(0, filesize) == "b6819af7882a880ab0119b79fa068177570e53cf205653e4091bdfafc7ccf8b8"
}
```

### Sample 66: `774813aa1ca069bf`

| Field | Value |
|---|---|
| SHA-256 | `774813aa1ca069bf99771e37766b073e569e7cfb5056593126598f5fae343661` |
| Family label | `unknown` |
| File name | `busywget.sh` |
| File type | `sh` |
| First seen | `2026-07-20 20:26:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f3b68c197aa920b3cdceef9e50d0d26` |
| SHA-1 | `0e913e1dffeee8878ab321026aa0873ec063e0df` |
| SHA-256 | `774813aa1ca069bf99771e37766b073e569e7cfb5056593126598f5fae343661` |
| SHA3-384 | `dea0114c6c8c9824a5ef7e25185f5d56733b53e46ebc1aa25de582b385fbcbb798a7af9d76d8eabd7160d8ff8655710f` |
| TLSH | `T1CB2104C5006449BDDC82AE48F77B98C4AA594696FE827F8EA9DC047AE55CD34F0CCAD0` |
| SSDEEP | `12:MCd9I+AA4eNIyJSDfKi+39k1V4HSgM/2n:HnjseNIDzKi+NKV4ygM/2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_774813aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774813aa1ca069bf99771e37766b073e569e7cfb5056593126598f5fae343661"
    family = "unknown"
    file_name = "busywget.sh"
    file_type = "sh"
    first_seen = "2026-07-20 20:26:47"
  condition:
    hash.sha256(0, filesize) == "774813aa1ca069bf99771e37766b073e569e7cfb5056593126598f5fae343661"
}
```

### Sample 67: `29b4af860c1a6f86`

| Field | Value |
|---|---|
| SHA-256 | `29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2` |
| Family label | `unknown` |
| File name | `29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2` |
| File type | `unknown` |
| First seen | `2026-07-20 20:19:46` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bddc96cf68f9203a53b78b8c77eea89` |
| SHA-256 | `29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_29b4af86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2"
    family = "unknown"
    file_name = "29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2"
    file_type = "unknown"
    first_seen = "2026-07-20 20:19:46"
  condition:
    hash.sha256(0, filesize) == "29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2"
}
```

### Sample 68: `72a5a6dd913263a9`

| Field | Value |
|---|---|
| SHA-256 | `72a5a6dd913263a9773df35c1ae3c5d0fea06bb7848c9ecf91c1ea8eca8f9979` |
| Family label | `Mirai` |
| File name | `morte.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 20:15:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a180f4c1432d2c3e01bad4d167c0859d` |
| SHA-1 | `0370f11475440cd78d91ce9ca9243f98dde0f29c` |
| SHA-256 | `72a5a6dd913263a9773df35c1ae3c5d0fea06bb7848c9ecf91c1ea8eca8f9979` |
| SHA3-384 | `6a6c2d41959a32fdd8b7e81f8dd3381ecf43efdacf991ad015a3bd631f5c4702e9ed14a94031bbd0c83d88338b220b26` |
| TLSH | `T13CA31916FDC18CFDC44AC03443BFB53ADD22F4EE0238B29B6BD4AE27690DE611A19955` |
| TELFHASH | `t1452163b82c9a379840e39268730fe5a6d82301313fa170e68e73add9de5bfd45d83052` |
| SSDEEP | `3072:d4DEFusTs0Hzc+OFq9E9ZvlP2lwqLH9i0eG:d4DE8sTpHzc+QfKwkc0eG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_72a5a6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72a5a6dd913263a9773df35c1ae3c5d0fea06bb7848c9ecf91c1ea8eca8f9979"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 20:15:53"
  condition:
    hash.sha256(0, filesize) == "72a5a6dd913263a9773df35c1ae3c5d0fea06bb7848c9ecf91c1ea8eca8f9979"
}
```

### Sample 69: `4dc8b56b03e7c8cf`

| Field | Value |
|---|---|
| SHA-256 | `4dc8b56b03e7c8cf3b12bf57c07e0bb9a61ecd18615ed60e2f0124ad9b4e9061` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-20 20:15:48` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48d1382b30de604dfb758c4c40157352` |
| SHA-1 | `0da31900db4a691d9c42b1f0500efb61332ea336` |
| SHA-256 | `4dc8b56b03e7c8cf3b12bf57c07e0bb9a61ecd18615ed60e2f0124ad9b4e9061` |
| SHA3-384 | `c4df3a3bdaec8d7d3a3421bf6cce2cd974d6bf9f1b6dd5ebc61d3de2d2b2b2ddcb042a4b04605c45740de76eea532594` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T1BA825B0FB9424726C0E110B49675877BDAB9A872338454DBF7D08AAD0B682D1FC3315F` |
| SSDEEP | `384:fIqQlV6lYR60LZu94gNTc9Qav8U9c2XF:7p049ta0UF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_4dc8b56b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dc8b56b03e7c8cf3b12bf57c07e0bb9a61ecd18615ed60e2f0124ad9b4e9061"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 20:15:48"
  condition:
    hash.sha256(0, filesize) == "4dc8b56b03e7c8cf3b12bf57c07e0bb9a61ecd18615ed60e2f0124ad9b4e9061"
}
```

### Sample 70: `7ac23035d89498bc`

| Field | Value |
|---|---|
| SHA-256 | `7ac23035d89498bc3d3b148d726bb072a07f7e579b55618ad5f686ef7048ade1` |
| Family label | `Mirai` |
| File name | `morte.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 20:14:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0191eb33489a385be4f7628e59de76` |
| SHA-1 | `75074dbd59dd4974b22c3a4e7a8a6acebe34dafb` |
| SHA-256 | `7ac23035d89498bc3d3b148d726bb072a07f7e579b55618ad5f686ef7048ade1` |
| SHA3-384 | `b6e70f2c6cb336232f0b60c0f3c7b553abfc964bdffda59c36daf3a47972b1a7ad89fd590abca39ff5aa9bc2db9fa0d6` |
| TLSH | `T15323F2F7212BBAB5D123C072ACAB53C0BD15B9595A479B2F1FF571488DE118C0ABDC42` |
| SSDEEP | `768:0ACjszYEfRY6jvJyiNQ5iP+h0b3WvnjEoTUV6tk7jihQ283xRGpPSkeNfx02y:zC6YYR1jkiNTPe0bWvINVdKhQZ3jGp6C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_7ac23035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac23035d89498bc3d3b148d726bb072a07f7e579b55618ad5f686ef7048ade1"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 20:14:59"
  condition:
    hash.sha256(0, filesize) == "7ac23035d89498bc3d3b148d726bb072a07f7e579b55618ad5f686ef7048ade1"
}
```

### Sample 71: `05feafe05fedb138`

| Field | Value |
|---|---|
| SHA-256 | `05feafe05fedb138116489ceca8a84b302ed59e2f3d18daa9527b057aa485c9a` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-20 19:59:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5348c5746c4c1521d36813b97e04e43` |
| SHA-1 | `fc739f2d544cf440c9e107c71137bdaecb3de59b` |
| SHA-256 | `05feafe05fedb138116489ceca8a84b302ed59e2f3d18daa9527b057aa485c9a` |
| SHA3-384 | `a872df88d9823115d3ffce2c7c35d12b5a4b1bda6503f41fb351843fd6af72e807610b2f983a4977506e2449c0b906c0` |
| TLSH | `T1730188EA8254680040AD961D32976094F420D3CF168A4B39BFAC6D3DABA8804F02AFC4` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohad3lKSH0FvXt9MZX:e9Qp+Msdw60Fvd9KX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_05feafe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05feafe05fedb138116489ceca8a84b302ed59e2f3d18daa9527b057aa485c9a"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-20 19:59:59"
  condition:
    hash.sha256(0, filesize) == "05feafe05fedb138116489ceca8a84b302ed59e2f3d18daa9527b057aa485c9a"
}
```

### Sample 72: `6ef76a3b50c9f704`

| Field | Value |
|---|---|
| SHA-256 | `6ef76a3b50c9f70408e74e4c15d986f94979711d35f3f6744d1ab61387214eb6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-20 19:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d19dbf2ae5a8c7350bf3424834ef7031` |
| SHA-1 | `1891576b13b73563d5bb08a0a0d00f6cb14aea9e` |
| SHA-256 | `6ef76a3b50c9f70408e74e4c15d986f94979711d35f3f6744d1ab61387214eb6` |
| SHA3-384 | `7f3302463c68da0e70b10fea6c747a2c0bf0b27ded6812aeb400dcf6c39a578f9a7ea726aa9ad2e436924c4c085d9eaf` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T162E6335862E010EDEAB3513CF9E169AAF948B8B613B3C5DF575842623C172D09D3EA13` |
| SSDEEP | `393216:+97ceQme+Ku/AXMCHWUjXLcuI3/PGTAI:+9AhmeUoXMb8XoH/O7` |
| ICON-DHASH | `98dcf8f8dcf8e144` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_6ef76a3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ef76a3b50c9f70408e74e4c15d986f94979711d35f3f6744d1ab61387214eb6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 19:52:09"
  condition:
    hash.sha256(0, filesize) == "6ef76a3b50c9f70408e74e4c15d986f94979711d35f3f6744d1ab61387214eb6"
}
```

### Sample 73: `84d07f96725bc87d`

| Field | Value |
|---|---|
| SHA-256 | `84d07f96725bc87d56f68936dd3879ffe67f1f8d694be9fbc4edd4a6d9a44615` |
| Family label | `unknown` |
| File name | `verification.ps1` |
| File type | `ps1` |
| First seen | `2026-07-20 19:46:08` |
| Reporter | `smica83` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bc77047dcd261da4ea5bcdd26db60b8` |
| SHA-1 | `7f49f6100a34e96847c741130683a3a8e7f0a0ae` |
| SHA-256 | `84d07f96725bc87d56f68936dd3879ffe67f1f8d694be9fbc4edd4a6d9a44615` |
| SHA3-384 | `c4078830c77b5a6591d19bf1be20e330af94cc789dc377a95b419e3ab9b11185365feb70ced1260a5aecb30eff9f3e0e` |
| TLSH | `T16A65E1E29F3BB41C979C4721D24FA64C2E854CD80D93B8E174DA0ACD67F622752E35B8` |
| SSDEEP | `24576:MGixYhKvR/kcpIS+O6hmbI1QGqkecRCrdBcp6G5DXc+Lc0fLaQ1U5bz9Y7/mxru+:Mp/kcOQ07EcpPcg1YwxnXkn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_84d07f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d07f96725bc87d56f68936dd3879ffe67f1f8d694be9fbc4edd4a6d9a44615"
    family = "unknown"
    file_name = "verification.ps1"
    file_type = "ps1"
    first_seen = "2026-07-20 19:46:08"
  condition:
    hash.sha256(0, filesize) == "84d07f96725bc87d56f68936dd3879ffe67f1f8d694be9fbc4edd4a6d9a44615"
}
```

### Sample 74: `2e086924a7835d46`

| Field | Value |
|---|---|
| SHA-256 | `2e086924a7835d4679749992f6b684ccf2fa5ab7f33fa69201b22ccf1f98571c` |
| Family label | `Mirai` |
| File name | `morte.mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 19:40:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48b67fb47a5245406898fd2cbe83e9b2` |
| SHA-1 | `d14830aa6f1ee3419d170f2054dfba493d141e77` |
| SHA-256 | `2e086924a7835d4679749992f6b684ccf2fa5ab7f33fa69201b22ccf1f98571c` |
| SHA3-384 | `4a12752b00865030c6dbf67a7d12265707fa9d255cb9ea3fd15f8d2b3d9ba7b82489bdcdb029f18871da3f7e50ccb329` |
| TLSH | `T163D3C609BB611FFBD8AFCC3706F91705288D595722A97B3AB530D818F64B24B19E3874` |
| SSDEEP | `3072:fYlmEdw0bmz0JpUDESDCE83UjiMXpHyMRvs3B:fYUEdw0bmz0JpCE6CEwUjXXpHy93` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_2e086924
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e086924a7835d4679749992f6b684ccf2fa5ab7f33fa69201b22ccf1f98571c"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:40:52"
  condition:
    hash.sha256(0, filesize) == "2e086924a7835d4679749992f6b684ccf2fa5ab7f33fa69201b22ccf1f98571c"
}
```

### Sample 75: `c165527a2aa356d0`

| Field | Value |
|---|---|
| SHA-256 | `c165527a2aa356d02f68fd695fbfe5ae9170eb8b6862e48cf9758e0ec6eebe31` |
| Family label | `Mirai` |
| File name | `morte.mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 19:39:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c253badd8eb347bb3a9643af1c5ade7` |
| SHA-1 | `cf3fcb48d31dd785cda536b15fd6ae8cbe5a0c54` |
| SHA-256 | `c165527a2aa356d02f68fd695fbfe5ae9170eb8b6862e48cf9758e0ec6eebe31` |
| SHA3-384 | `2479762798b90ea53fda1d6393b471dbd42d7c5b4b2cd65d6b7a8255a3f17454a01149b609774adfbcf7836dac83941e` |
| TLSH | `T13323F19CEDD13882DE9A0CFCE3CA04637AE5A054133A1FAE8B60CE45FB6E51DB95C154` |
| SSDEEP | `768:HzqjkFaqefzXE0hpSSyZ7c/49B87YMkAOx/mcgAl/Z58Va/h/Yueo3gQzWK:HzILqyzXMqAnaluIYyaxYulJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_c165527a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c165527a2aa356d02f68fd695fbfe5ae9170eb8b6862e48cf9758e0ec6eebe31"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:39:58"
  condition:
    hash.sha256(0, filesize) == "c165527a2aa356d02f68fd695fbfe5ae9170eb8b6862e48cf9758e0ec6eebe31"
}
```

### Sample 76: `af9a6dacb2a96188`

| Field | Value |
|---|---|
| SHA-256 | `af9a6dacb2a9618866cf398d615b2fe1c1c98ec7254d38a01c7c2d6869821bbe` |
| Family label | `Gh0stRAT` |
| File name | `moshou-xinshouhezi.zip` |
| File type | `zip` |
| First seen | `2026-07-20 19:38:23` |
| Reporter | `smica83` |
| Tags | `Gh0stRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76ddd649d116b9b9df218d063580024c` |
| SHA-1 | `eb2c53d339d0c893383ed9ac3a33462c6995def5` |
| SHA-256 | `af9a6dacb2a9618866cf398d615b2fe1c1c98ec7254d38a01c7c2d6869821bbe` |
| SHA3-384 | `ab9d6b92ee0707a3851b6600497e1c56fb2d0f88ccb1710f63e5a4c14cbd1e8fe9dd59bf45ce99be5a0017cb13e6553a` |
| TLSH | `T15A27336CF4C998F3F816800CBE0899D763C43C2797B952C2A78BD9D9DF9EB259200395` |
| SSDEEP | `393216:F5leE1/UVJ1iIx9Vh6WTON7qFO+X7rVLjmOfKdW/6NBo6aYyC/osW:zl/UJ19mN7PS3m2KNOZ5Cg9` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_076_af9a6dac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af9a6dacb2a9618866cf398d615b2fe1c1c98ec7254d38a01c7c2d6869821bbe"
    family = "Gh0stRAT"
    file_name = "moshou-xinshouhezi.zip"
    file_type = "zip"
    first_seen = "2026-07-20 19:38:23"
  condition:
    hash.sha256(0, filesize) == "af9a6dacb2a9618866cf398d615b2fe1c1c98ec7254d38a01c7c2d6869821bbe"
}
```

### Sample 77: `cdf7dbac5c8ca636`

| Field | Value |
|---|---|
| SHA-256 | `cdf7dbac5c8ca636350541007bf67ac05634ef36dbf64ffd7c73dbc6db5bb280` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 19:37:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25d7c97a437df82922b7e2a1569dac6c` |
| SHA-1 | `86f6ea17c404356f5da710231fa774514750bc23` |
| SHA-256 | `cdf7dbac5c8ca636350541007bf67ac05634ef36dbf64ffd7c73dbc6db5bb280` |
| SHA3-384 | `d042ae1afaf5aa8c47c37ebd6b307e815cc9cc2d4a3f1d2e6722beed4c6bfe0caab9773f643f1283fa19c47e6b3f583c` |
| TLSH | `T10BC33B0779C18AFEC486D67803BF7526C522F83E1B36338B67D47D693A09AD42A1D319` |
| TELFHASH | `t1c4314231477155292eb0c914acec97b2651a87171748ee33ce31c89c242a0aef93fc0f` |
| SSDEEP | `3072:S6SblaZFi4q0KI1XeN31xwnPEbt+uYr0uBtuerGulNpS:tyUFi4ZNEDwPRuYpBt9rGulNpS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_cdf7dbac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdf7dbac5c8ca636350541007bf67ac05634ef36dbf64ffd7c73dbc6db5bb280"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 19:37:43"
  condition:
    hash.sha256(0, filesize) == "cdf7dbac5c8ca636350541007bf67ac05634ef36dbf64ffd7c73dbc6db5bb280"
}
```

### Sample 78: `bce3c7ad26433b03`

| Field | Value |
|---|---|
| SHA-256 | `bce3c7ad26433b03c0aeb8d987e9b6b889582fe8ef870949329abfaa175c0e81` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-20 19:35:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `530e7a38fad056db86acc3271c1647af` |
| SHA-1 | `9397e678fcd63e9d087a8479e192791e592e41f3` |
| SHA-256 | `bce3c7ad26433b03c0aeb8d987e9b6b889582fe8ef870949329abfaa175c0e81` |
| SHA3-384 | `07cc2e5bdae5b43b4e17f3fd96a80815fd0244a892567ccc35e120421237daf291c90fb45496b5de7dad5529c2789972` |
| TLSH | `T19214A65E6E228F7EF76C873047B78A34976923D627E0D684D1ACC2115F2029E541FFA8` |
| TELFHASH | `t1cd4194180d7417b4a7756c5d089dfb2bd6a330eb7e162c378e51e86ae769b838d10c1c` |
| SSDEEP | `3072:+k4b3i76UkkeAnZTnXKOlca2upGfiWUdaaBbY+2f1SoEw:+k4b3q6UkkeAnZ22f8fudtB2NSO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_bce3c7ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bce3c7ad26433b03c0aeb8d987e9b6b889582fe8ef870949329abfaa175c0e81"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-20 19:35:37"
  condition:
    hash.sha256(0, filesize) == "bce3c7ad26433b03c0aeb8d987e9b6b889582fe8ef870949329abfaa175c0e81"
}
```

### Sample 79: `17d1b0c433da78f9`

| Field | Value |
|---|---|
| SHA-256 | `17d1b0c433da78f9a1de8e1ebb04e3174961f8b97aa5d489b21f28dec1c2ac15` |
| Family label | `Mirai` |
| File name | `morte.m68k` |
| File type | `elf` |
| First seen | `2026-07-20 19:34:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `944f1df7d08cbd62983083bd586265a9` |
| SHA-1 | `57268ed5426392cc682eb19ac5ad56f0caee7f5d` |
| SHA-256 | `17d1b0c433da78f9a1de8e1ebb04e3174961f8b97aa5d489b21f28dec1c2ac15` |
| SHA3-384 | `c6038ff9fefea45a42712bd5267e0c06a0e38519c698dece765df78b01d345ef52cdfe9c89d5d362c2ebefc80e748cbf` |
| TLSH | `T1F7B35BCAF401CD7DF90FDABA4467090AB930A3A166C31F26625BFD93AC331A57D12D85` |
| SSDEEP | `3072:vXgbJa9qvuV2/UZfiS3T2HIvBFJ3oMZJ+NigpmyuTpuh:fguqvPOfiYTPRHZsNkyuwh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_17d1b0c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17d1b0c433da78f9a1de8e1ebb04e3174961f8b97aa5d489b21f28dec1c2ac15"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 19:34:35"
  condition:
    hash.sha256(0, filesize) == "17d1b0c433da78f9a1de8e1ebb04e3174961f8b97aa5d489b21f28dec1c2ac15"
}
```

### Sample 80: `f2938a785b50c89b`

| Field | Value |
|---|---|
| SHA-256 | `f2938a785b50c89b61abcfe405a5ecececba42d259eba1ccceed5e32821da33d` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-20 19:34:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f918ecc354aa32b346c0a8b660fe0023` |
| SHA-1 | `80641950e1215dceb92d3a54df9a327a9a30d2f6` |
| SHA-256 | `f2938a785b50c89b61abcfe405a5ecececba42d259eba1ccceed5e32821da33d` |
| SHA3-384 | `5002d493ef6ba8a2da3fd7ab48848dee3bea035b278e576a3ed2db68db4ef8507c1ebb31452194fbf3678adbb3f2b2e7` |
| TLSH | `T1D953022C0104D9E9CFFF36B5118A02551C72CFBBACA1E9063C47C95565A41EB889F9EE` |
| SSDEEP | `1536:mGy7yunA6F/c2KbJyx09nv578K5sG3Jt8aVEW5:VyPnl9WBJoaVES` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_f2938a78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2938a785b50c89b61abcfe405a5ecececba42d259eba1ccceed5e32821da33d"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-20 19:34:33"
  condition:
    hash.sha256(0, filesize) == "f2938a785b50c89b61abcfe405a5ecececba42d259eba1ccceed5e32821da33d"
}
```

### Sample 81: `83fee47d6e11339c`

| Field | Value |
|---|---|
| SHA-256 | `83fee47d6e11339cbd8af4546a6db2e7b4b29387533f81e7c082d44cafe3ed56` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-20 19:22:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae5ed82297cf4b4279a40b63e6889902` |
| SHA-1 | `20f54d041e1e9dbb5ef3ea335df9aee4135f1a36` |
| SHA-256 | `83fee47d6e11339cbd8af4546a6db2e7b4b29387533f81e7c082d44cafe3ed56` |
| SHA3-384 | `f99b1a67681d7c9967d400157e70d2292e4fc9a8878b373b3489999a966471faacfe27e7c70f971db9bf5d1f8e15f259` |
| TLSH | `T1F304F80AAF601EF7D86FCC3746E94B0625CC645322A43B757538E928F64A54F4AE3CB4` |
| SSDEEP | `3072:rLwsaiCL6tXkpTPIAQwQoRrHUphJAUIW38XMxqHOnbv:vwsPkPQwQoRrE/bIQ8XMdv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_83fee47d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83fee47d6e11339cbd8af4546a6db2e7b4b29387533f81e7c082d44cafe3ed56"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-20 19:22:26"
  condition:
    hash.sha256(0, filesize) == "83fee47d6e11339cbd8af4546a6db2e7b4b29387533f81e7c082d44cafe3ed56"
}
```

### Sample 82: `e10229824df64c0d`

| Field | Value |
|---|---|
| SHA-256 | `e10229824df64c0d22d67af78f9be8649429cdc3858fc905aba4bb57a98acb3f` |
| Family label | `Mirai` |
| File name | `morte.arc` |
| File type | `elf` |
| First seen | `2026-07-20 19:20:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea82bd83071b5bca3a41d96cdd8e3a64` |
| SHA-1 | `5b53f67d338b7356134e404658d65c46db8ab52a` |
| SHA-256 | `e10229824df64c0d22d67af78f9be8649429cdc3858fc905aba4bb57a98acb3f` |
| SHA3-384 | `fee2435fd5216863410aeab1651887f1da331aa773ddd395608065b0b5a18717ec3bfd587868dbc7e2cdc8f286e2e00a` |
| TLSH | `T14CD3AE97F74724A1C86302F40BCB4F9D2E6322829F5B98D77C6F2A7719760DB4906B81` |
| SSDEEP | `3072:CQJsSSQvhYt3VV+Xt9Pb80NSTiBhluyngDcwq:CQLNmtL+Xw4acwq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_e1022982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e10229824df64c0d22d67af78f9be8649429cdc3858fc905aba4bb57a98acb3f"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-07-20 19:20:11"
  condition:
    hash.sha256(0, filesize) == "e10229824df64c0d22d67af78f9be8649429cdc3858fc905aba4bb57a98acb3f"
}
```

### Sample 83: `67229a5054aa6e8c`

| Field | Value |
|---|---|
| SHA-256 | `67229a5054aa6e8c7f7f05bdff86da66b8e54363a455a8f902141ed0b39fcdec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-20 19:17:28` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99268cf298b5143bb60bcbc49cbd5943` |
| SHA-1 | `bef29d60a5f891f694d1b806b9aa3af1211bc99a` |
| SHA-256 | `67229a5054aa6e8c7f7f05bdff86da66b8e54363a455a8f902141ed0b39fcdec` |
| SHA3-384 | `94b2607c251962807bc17916a8301853264bf84ec448afade4f2045d0f9870421d3032f1a9e0f1636a6baa3fbf7bddf0` |
| IMPHASH | `1e10de300bb84d91d7b9493496b37e24` |
| TLSH | `T13AD37B6767EA30F9E2778238C8514655E773B8315761AFEF07A042992F236E08D39F21` |
| SSDEEP | `3072:pLrIsu+OC6if92e+qFMLM62pdGAo7eRBG0oTWz/UH7EoCya:ZrI4OC64XFMA64GAZzfsWz/y1Cya` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_67229a50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67229a5054aa6e8c7f7f05bdff86da66b8e54363a455a8f902141ed0b39fcdec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 19:17:28"
  condition:
    hash.sha256(0, filesize) == "67229a5054aa6e8c7f7f05bdff86da66b8e54363a455a8f902141ed0b39fcdec"
}
```

### Sample 84: `baf0843bbc852500`

| Field | Value |
|---|---|
| SHA-256 | `baf0843bbc852500c72e11c41c0c279a5d94b1b395ebe6403ed4e68473caac20` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 19:14:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8522ff2241ace66eeef11a56df6425e` |
| SHA-1 | `ed1af398ef03009adc9d3db0d642e44c4ee51c16` |
| SHA-256 | `baf0843bbc852500c72e11c41c0c279a5d94b1b395ebe6403ed4e68473caac20` |
| SHA3-384 | `769ed96d7996ddad4be928eb80afc3ffa2a8eee81b04c9e30a7f4924e5ce8ad4711508a0706049d715c3f547bd916e89` |
| TLSH | `T1AF045C49AE342BEBC05FCE30052E930B11DD945FA2F6B77DA678CD4C399A24859F3894` |
| TELFHASH | `t16a31cfb08b7b65119ac5c7ec88edb75a491e8515470adf33fd3180ac90260ede22ad4f` |
| SSDEEP | `3072:yd8q5aV2iRkzXzW3OdSGozEwhmpiHigjmZYvJ5VSX5fd1DMkc:ydb5aQiRkzXy3ySGozEwhmpiHyZYvJMc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_baf0843b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf0843bbc852500c72e11c41c0c279a5d94b1b395ebe6403ed4e68473caac20"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:49"
  condition:
    hash.sha256(0, filesize) == "baf0843bbc852500c72e11c41c0c279a5d94b1b395ebe6403ed4e68473caac20"
}
```

### Sample 85: `16e1cd6a877ff9c0`

| Field | Value |
|---|---|
| SHA-256 | `16e1cd6a877ff9c0c0c4fbe3bb87a6077ca30dbe9443b8096456a7ad4dc63955` |
| Family label | `Mirai` |
| File name | `morte.ppc` |
| File type | `elf` |
| First seen | `2026-07-20 19:14:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9420d8b22ef1c9ee3632e0bec7e24b3d` |
| SHA-1 | `785346da4d2c9e00b8af69795a4ec039aa51890d` |
| SHA-256 | `16e1cd6a877ff9c0c0c4fbe3bb87a6077ca30dbe9443b8096456a7ad4dc63955` |
| SHA3-384 | `66361b1aca12b7513f981d26b9af157bc6038f2c78eb539a862cdaed4cd07e5f138bbdba119a6932282ecbe4ea0e6334` |
| TLSH | `T157B35B02B31C0F57C1970AB02E3F17E587BEE5D121E0BA89651FDB5686B6E37144AEC8` |
| SSDEEP | `1536:FBUs1+65Uhz9E0FUrBhyKt2c4cH9q+puhuOYffFgJi:FBUs0lUrOt09JuaSJi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_16e1cd6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e1cd6a877ff9c0c0c4fbe3bb87a6077ca30dbe9443b8096456a7ad4dc63955"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:47"
  condition:
    hash.sha256(0, filesize) == "16e1cd6a877ff9c0c0c4fbe3bb87a6077ca30dbe9443b8096456a7ad4dc63955"
}
```

### Sample 86: `973f0b790ce63155`

| Field | Value |
|---|---|
| SHA-256 | `973f0b790ce63155e93a735c98334879ffcda03fdd4976afc9e18fefa8af854f` |
| Family label | `Mirai` |
| File name | `morte.arm` |
| File type | `elf` |
| First seen | `2026-07-20 19:14:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25d7f30fb4dc7d5efef815694ee96edd` |
| SHA-1 | `24c8aeeb22eccb465c8ba5f5c8370bdc8972caed` |
| SHA-256 | `973f0b790ce63155e93a735c98334879ffcda03fdd4976afc9e18fefa8af854f` |
| SHA3-384 | `866f23e97e187ebc38ad94f5cf786829f1503422b74279672a4b21ffbb4488b78e3d8dd13c97f879d41aa60f87ee5fa6` |
| TLSH | `T1DCB32A45FC829623C6D7237BF66E428D372263E8D3DA3107DE256F21338652B0DA7A45` |
| TELFHASH | `t189c080156f342ddc7fc42940460577061ed4f07a55443852d558127fc958546b43df07` |
| SSDEEP | `1536:Eq8q7gFsYTo41vn2Ue0/Zd3PobzlhCWc4obhuP4m3pBVaUhvGC:Eqn7gz841ulZI4obhnUnGC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_973f0b79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "973f0b790ce63155e93a735c98334879ffcda03fdd4976afc9e18fefa8af854f"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:44"
  condition:
    hash.sha256(0, filesize) == "973f0b790ce63155e93a735c98334879ffcda03fdd4976afc9e18fefa8af854f"
}
```

### Sample 87: `c1194291bfd88db4`

| Field | Value |
|---|---|
| SHA-256 | `c1194291bfd88db485cf45f31cb17a04b261de1455047a4a6e330b26fb87877a` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-20 19:14:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50146d257ad2356cdf2066ca699a7377` |
| SHA-1 | `3ab485ce98a36e4d61a00b976f5d7c3f37f0a5ac` |
| SHA-256 | `c1194291bfd88db485cf45f31cb17a04b261de1455047a4a6e330b26fb87877a` |
| SHA3-384 | `655d95f14dcf61e27edbb7d3d8a025e387a25afdf9f29742954b3ce37f78fb7c20c0f7a2a71a07b8f4427005ea20e567` |
| TLSH | `T1C6C31B99FC90DE52C6D52579FA5E418C332317B8C3DA7206CE209F3477E796A0A3A942` |
| SSDEEP | `3072:i9Jz4jHUozieUsNUQ4g8OMCBXd6cRWNSFNz+sdw5mf1Dl:iDQHQsNUQ4g8OxBXd6MFNzpqm95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_c1194291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1194291bfd88db485cf45f31cb17a04b261de1455047a4a6e330b26fb87877a"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:39"
  condition:
    hash.sha256(0, filesize) == "c1194291bfd88db485cf45f31cb17a04b261de1455047a4a6e330b26fb87877a"
}
```

### Sample 88: `b96fe3c442ff0efc`

| Field | Value |
|---|---|
| SHA-256 | `b96fe3c442ff0efc544510eb8c724be73a2eb7f0c21f21b6ba68e678778d129d` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-07-20 19:14:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `add54bd78384715bb05daf9a3d7d7c13` |
| SHA-1 | `67aef862e9b89d8c10981adc1c5fdb1f11ccb11a` |
| SHA-256 | `b96fe3c442ff0efc544510eb8c724be73a2eb7f0c21f21b6ba68e678778d129d` |
| SHA3-384 | `ce6c78cc82d2edf1f273308338cd7009a400d3ba44041e6be5d47d8eaa88db86243dba7c9e971b4c1118de82bed420dc` |
| TLSH | `T1BAC329A9F890DE52C6D526B6FB4E418C33231778C3DE7106CE149E3467FB95A0A3E942` |
| SSDEEP | `3072:QuIBvPRfsNDUxMa3tIDrcYEEUIAyMW0NwhBigpmqzWNiF+WOud5mf1Dl:QJ5GytercYEEUIAyMWGwiOmqzpJ7m95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_b96fe3c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96fe3c442ff0efc544510eb8c724be73a2eb7f0c21f21b6ba68e678778d129d"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:10"
  condition:
    hash.sha256(0, filesize) == "b96fe3c442ff0efc544510eb8c724be73a2eb7f0c21f21b6ba68e678778d129d"
}
```

### Sample 89: `0e2f88421bec2bf2`

| Field | Value |
|---|---|
| SHA-256 | `0e2f88421bec2bf2fb22c26c8bd5b10469921fc66310b01b39937487d5a1904f` |
| Family label | `Mirai` |
| File name | `morte.arm5` |
| File type | `elf` |
| First seen | `2026-07-20 19:14:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2144842ddb06de51407e17510420ed35` |
| SHA-1 | `ecd2ae6ccea1e8a5393a1e6aae0d21ac7f127317` |
| SHA-256 | `0e2f88421bec2bf2fb22c26c8bd5b10469921fc66310b01b39937487d5a1904f` |
| SHA3-384 | `8a81ea6cf54d8eb29bbb3dee7a5f6fde35602e4216691b22dbf27e9f24279d1135a55b865853c7810808d520ccf6ebe4` |
| TLSH | `T1C6731942BC828A2AC6D013BDA67EA68D33A1B3E5D2DE3117EE145F117BC520F5D67E40` |
| TELFHASH | `t10fe06140fe764b1884e75a34ecdd47b495116217a1664710cf54daf0883f15ca71cd5e` |
| SSDEEP | `1536:CIJdLxqIUWI7z1Kd4joarU2oIZe0XGginEUKYgO0MQz:pzlqIUW81U29a/KpMQz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_0e2f8842
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e2f88421bec2bf2fb22c26c8bd5b10469921fc66310b01b39937487d5a1904f"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:03"
  condition:
    hash.sha256(0, filesize) == "0e2f88421bec2bf2fb22c26c8bd5b10469921fc66310b01b39937487d5a1904f"
}
```

### Sample 90: `9880eb40dbffc85f`

| Field | Value |
|---|---|
| SHA-256 | `9880eb40dbffc85f31d411dc5f28344ef101494dd2944a87bfa1f87a917b83bb` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-20 19:14:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8d8958142ea407b94219b837555fa89` |
| SHA-1 | `11188183348a217776a03a62f146dc315ab2dbbc` |
| SHA-256 | `9880eb40dbffc85f31d411dc5f28344ef101494dd2944a87bfa1f87a917b83bb` |
| SHA3-384 | `c758cc6248fa8befebcc9867e46a4251991dff6ae1780fe798236c25abdd22949ad1450309baba63e81629c1119407af` |
| TLSH | `T168C34902B46148FCC156C474C77FE927EA31785E13343A6F2B84BA712E22E755F0AB96` |
| SSDEEP | `1536:Cl+xWDOtHexNDVWt49uJU7YBGPKca4SCwJUZPFauU6zp4iHl1/s9GS/ziD5CaG48:Cl+pexNDO2kJGycfHVFI9G2y5CaG4KV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_9880eb40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9880eb40dbffc85f31d411dc5f28344ef101494dd2944a87bfa1f87a917b83bb"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:00"
  condition:
    hash.sha256(0, filesize) == "9880eb40dbffc85f31d411dc5f28344ef101494dd2944a87bfa1f87a917b83bb"
}
```

### Sample 91: `021427534dbf7d13`

| Field | Value |
|---|---|
| SHA-256 | `021427534dbf7d135a102de94627a2809ea47ed6dd9753116999aa50989771c9` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-20 19:13:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4d2627fbd082385b1274e3e31a1f8c0` |
| SHA-1 | `453d181ef5b33852e635b091c0cec41007e4bcc5` |
| SHA-256 | `021427534dbf7d135a102de94627a2809ea47ed6dd9753116999aa50989771c9` |
| SHA3-384 | `95b0a69237e6b244132bc9b021d9396f8246e1f97e3df9dfaafafa13c285956185d17db190375a0109ef129b33236a85` |
| TLSH | `T1B58312D24EAD11BA3BFBEEFA257F058E82856351771196363D40C5B83E320C1D292A1C` |
| SSDEEP | `1536:S7N4aVi5FLkGQSiHzDkjgpzFsw6YUVVvbn6euCRZ5tsp9Hr4IwsYW4fha02TL:/aViflQSiTwjgpzFtUVVvT68RZMp9HrZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_02142753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021427534dbf7d135a102de94627a2809ea47ed6dd9753116999aa50989771c9"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:12"
  condition:
    hash.sha256(0, filesize) == "021427534dbf7d135a102de94627a2809ea47ed6dd9753116999aa50989771c9"
}
```

### Sample 92: `90b9875329d3272f`

| Field | Value |
|---|---|
| SHA-256 | `90b9875329d3272f60376d93c7096818da5264bb7f264c2f76ec7b528be69c87` |
| Family label | `Mirai` |
| File name | `morte.ppc` |
| File type | `elf` |
| First seen | `2026-07-20 19:13:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `488ab23871e8fd840d56a8340f27b25b` |
| SHA-1 | `62ecfb43348a27ba1016dae96f0e1760de7dc8ec` |
| SHA-256 | `90b9875329d3272f60376d93c7096818da5264bb7f264c2f76ec7b528be69c87` |
| SHA3-384 | `052c4717452c16d4ec4de8058ae1f11dd0bd15f5e17882bd8bd0187fdaca39bedeccbd0ad43ce60901a295589737f99c` |
| TLSH | `T17A13F1ACF57C1959CA2E3E634D50FFD767F48E09CE8692111051FE0EA92AC8522C2ADC` |
| SSDEEP | `768:QAKxjI20hvqUREwtm4HWRiMTEoQVIb5HY4Ni8zPjr4Vcgl/URwhC962wHATi5xYq:QAKxjIxhC2tC/YoQadHYXWAC9lwScY4r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_90b98753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90b9875329d3272f60376d93c7096818da5264bb7f264c2f76ec7b528be69c87"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:11"
  condition:
    hash.sha256(0, filesize) == "90b9875329d3272f60376d93c7096818da5264bb7f264c2f76ec7b528be69c87"
}
```

### Sample 93: `e706cc6ce9f500e1`

| Field | Value |
|---|---|
| SHA-256 | `e706cc6ce9f500e179b0cdebca1f60462591f4d67a54cc785c2217d3665100fd` |
| Family label | `Mirai` |
| File name | `morte.arm` |
| File type | `elf` |
| First seen | `2026-07-20 19:13:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e260c74e8ee5a213abbab2edc21a65a` |
| SHA-1 | `8d8a3b44a2f13c366011942bffa6af4e9a50d177` |
| SHA-256 | `e706cc6ce9f500e179b0cdebca1f60462591f4d67a54cc785c2217d3665100fd` |
| SHA3-384 | `bec60ba476f15aa086c641175628a4f3698c6644b7155d5155d9ec4ae8500e0a89763cba5c1088475af7daea483aac3d` |
| TLSH | `T11823F2112BB62FE5A2201C32CD8ACE5BE7F24DF99DFBF0411615878066E45CDA5BA313` |
| SSDEEP | `768:uXhkmzAEmsQHjPG2HZ7/QhejrHSzJXNUtXi0ElyhXH6lFDApJEQVi7Is3Uozc:uR8THTRHRrjrHSzFR0ElEaD0AQoRzc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_e706cc6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e706cc6ce9f500e179b0cdebca1f60462591f4d67a54cc785c2217d3665100fd"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:09"
  condition:
    hash.sha256(0, filesize) == "e706cc6ce9f500e179b0cdebca1f60462591f4d67a54cc785c2217d3665100fd"
}
```

### Sample 94: `451e62772cb780fa`

| Field | Value |
|---|---|
| SHA-256 | `451e62772cb780fa8cd93a36f5041c349d62dfb83e6c9879c082050b55a5b444` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-20 19:13:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ae0193b1a075db07046ad7f695c6cce` |
| SHA-1 | `b4c606f432085f215b1be83d2082cb0c2d32fa7c` |
| SHA-256 | `451e62772cb780fa8cd93a36f5041c349d62dfb83e6c9879c082050b55a5b444` |
| SHA3-384 | `f900f49911d2d9e13fb7b706f862d5e96b42717c04b930ed7e8dc144a9d53d03d8c887d7307c888ae4ca0b2bfa4253e4` |
| TLSH | `T1894302A4EEC36971EFB81D32EC674027B7C546B06DE677EDA21901EC3AB504928E4096` |
| SSDEEP | `1536:BSLvjxPkC/fXZZ5Y9NvHX7NPd5X38rE1oaXFIbuWAMf7:kLv1PkCnZ47NvH8AZXKCwT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_451e6277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451e62772cb780fa8cd93a36f5041c349d62dfb83e6c9879c082050b55a5b444"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:08"
  condition:
    hash.sha256(0, filesize) == "451e62772cb780fa8cd93a36f5041c349d62dfb83e6c9879c082050b55a5b444"
}
```

### Sample 95: `53f741e54d11c319`

| Field | Value |
|---|---|
| SHA-256 | `53f741e54d11c319bcf5a268a5325208ec99cd2706c1932f9f6e3193044f871a` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-20 19:11:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c99c589001bed553523bd56c9d604b5` |
| SHA-1 | `5a9cbaf66b252ec3987027dd1851d9ea097bd5cc` |
| SHA-256 | `53f741e54d11c319bcf5a268a5325208ec99cd2706c1932f9f6e3193044f871a` |
| SHA3-384 | `48dc294d38b32a89309f909fa86288872226797da7184aa03b3a31770213818b2326cb3f6af135547bb7894cda8d5b35` |
| TLSH | `T155B36CC4F687C0F9E80744718036B33FC73295298025CAAADF6AAE76DE67641D61A31C` |
| TELFHASH | `t1675115f57a6e1ce8b7d06802930e6f22ad5da777242037a245f3d53431abd4252bac3d` |
| SSDEEP | `1536:WKIE20iBxucPpn5F8h0jAO04kKBc4RWs8S0Ss67tXoozIabsp6688:nIoUPBqEAd4TqdfSt7tXbon` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_53f741e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53f741e54d11c319bcf5a268a5325208ec99cd2706c1932f9f6e3193044f871a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:57"
  condition:
    hash.sha256(0, filesize) == "53f741e54d11c319bcf5a268a5325208ec99cd2706c1932f9f6e3193044f871a"
}
```

### Sample 96: `ff363cb6f29a269f`

| Field | Value |
|---|---|
| SHA-256 | `ff363cb6f29a269fc7763c2a5ea564b0d45ecf64b422d024bcf0912877ed075f` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-20 19:11:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e642f72b0d667ca5be1095c67aea927d` |
| SHA-1 | `ea4746588c41814b2f4b9b22637397bb7d425b6b` |
| SHA-256 | `ff363cb6f29a269fc7763c2a5ea564b0d45ecf64b422d024bcf0912877ed075f` |
| SHA3-384 | `eb82ceeaff5402b0ada3ed23089e351baef1841e22b200b602d3148310b8506e09cfdef767a43360118ff7ef1c6cf1d8` |
| TLSH | `T193D3F849BC819B10D9DA35FAFE4F028933575B6CE3FE7202D9205B2127CAA5B0F76512` |
| TELFHASH | `t1cca01120ba0ac808a88a80be0000000a8b08a8e083303c2aba2a822b8220c022332002` |
| SSDEEP | `3072:cGLhjcafpLSTtxEvuxgvaLiKLUZyQxh45NRMHp:cYhD+txyu+vaLiKLUZyWqNiHp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_ff363cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff363cb6f29a269fc7763c2a5ea564b0d45ecf64b422d024bcf0912877ed075f"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:53"
  condition:
    hash.sha256(0, filesize) == "ff363cb6f29a269fc7763c2a5ea564b0d45ecf64b422d024bcf0912877ed075f"
}
```

### Sample 97: `8e5fe294c314bb1c`

| Field | Value |
|---|---|
| SHA-256 | `8e5fe294c314bb1c2dbfa2ff6225b79380a5494fa70ecb1b8f1e6cf725a61427` |
| Family label | `Mirai` |
| File name | `morte.i686` |
| File type | `elf` |
| First seen | `2026-07-20 19:11:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe808fb7352c278f377e10e68ab0fa51` |
| SHA-1 | `a81c9a6a152cab783048acee9e5ca148e73b4918` |
| SHA-256 | `8e5fe294c314bb1c2dbfa2ff6225b79380a5494fa70ecb1b8f1e6cf725a61427` |
| SHA3-384 | `6b443ba659d3b5bf1367c5e3cc0807b726d8da6f3f86c83e49d2d59ec3d9ca2e3a3d081959eb890a71ddbd34a642466c` |
| TLSH | `T107B328C2F98B81F6D00B88306066F63FDA32D5E94171C65DEF9A9F36DB77242920264D` |
| TELFHASH | `t19631b1fa56790de59fe4cd02f28d9b20dd1e77b7282436a309b75810722314193bbd39` |
| SSDEEP | `1536:K3TKBqUN5T9pXpFz+7H7OoHWxwrn1RvTEhMU3y3vWPamwSrH1apoWD3sYHuxotV/:KD43p7SeoHWy7bLEF3lSmwSrVaGOH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_8e5fe294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e5fe294c314bb1c2dbfa2ff6225b79380a5494fa70ecb1b8f1e6cf725a61427"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:50"
  condition:
    hash.sha256(0, filesize) == "8e5fe294c314bb1c2dbfa2ff6225b79380a5494fa70ecb1b8f1e6cf725a61427"
}
```

### Sample 98: `993012e0659b402b`

| Field | Value |
|---|---|
| SHA-256 | `993012e0659b402b9ad154ffbbc6d7ba0c69dc79fcf63cc23886ddd6286e79e4` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-20 19:11:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab2276d880edd11e081e72bbaf867af8` |
| SHA-1 | `fa0d6c790c1605fe39c449b3be07b33f5e7fe0ae` |
| SHA-256 | `993012e0659b402b9ad154ffbbc6d7ba0c69dc79fcf63cc23886ddd6286e79e4` |
| SHA3-384 | `f5964eb5d18bd04ecc98749f78f3ac483fc2b5820ba308c9faefe32171cbdb7b99ec6a3415331e73c79b202ddef574b9` |
| TLSH | `T1AC042A5F7720CF61C329C53045F38B9666A922522BD2C889F35CDE087E65389A92FFD4` |
| TELFHASH | `t16a31cfb08b7b65119ac5c7ec88edb75a491e8515470adf33fd3180ac90260ede22ad4f` |
| SSDEEP | `3072:mqS754eB/M7Pzpc0Zv/28r51TYWL/TH574ecSQX0Kb1DNjC:pSg28XbvG3dkKhdC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_993012e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "993012e0659b402b9ad154ffbbc6d7ba0c69dc79fcf63cc23886ddd6286e79e4"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:46"
  condition:
    hash.sha256(0, filesize) == "993012e0659b402b9ad154ffbbc6d7ba0c69dc79fcf63cc23886ddd6286e79e4"
}
```

### Sample 99: `1684d94aee96c6c4`

| Field | Value |
|---|---|
| SHA-256 | `1684d94aee96c6c48111d57b4c1999cad4f4c490091a6b974492bef7a4519109` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-20 19:11:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58b3a8858337db98ed08899a995d8f9f` |
| SHA-1 | `32cdf72049b323cf020fdf1d6141abe623377066` |
| SHA-256 | `1684d94aee96c6c48111d57b4c1999cad4f4c490091a6b974492bef7a4519109` |
| SHA3-384 | `5bb9b546842850e60ed5b93168dd189597e9b1bd75d7922c686c397ae8723e3355320d1eb2c7d25d3a5d87e39ea7163c` |
| TLSH | `T1B3E33B45FC509B26C6D3227BFF4E428D772A1768D3EE320399256F20379A95B0E77242` |
| TELFHASH | `t1fce06137df201f9c1bd49136c0f5e11c41b5318a1b214008079daecb4b9b2cdb52853f` |
| SSDEEP | `1536:xwfp4C9pIOGQG/qAC8NIo8PFlhN9IPhHetADL/7T5xUPp8YZXOOxdsSTNB2lcWwy:xrCPPGiJNCEtAn7FGPpPNaShT4p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_1684d94a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1684d94aee96c6c48111d57b4c1999cad4f4c490091a6b974492bef7a4519109"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:34"
  condition:
    hash.sha256(0, filesize) == "1684d94aee96c6c48111d57b4c1999cad4f4c490091a6b974492bef7a4519109"
}
```

### Sample 100: `f78648c17aa133d3`

| Field | Value |
|---|---|
| SHA-256 | `f78648c17aa133d312e0255869f5b35aae1ca7674349e8a050df2da8c9e25d9a` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-20 19:11:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07cf9a85a3ab283d66ce82cbcfdecbb1` |
| SHA-1 | `95691dedfe8341a3e5f9164b620f384d6cc393f3` |
| SHA-256 | `f78648c17aa133d312e0255869f5b35aae1ca7674349e8a050df2da8c9e25d9a` |
| SHA3-384 | `a23e9e6c3d2ad9eab8251d7c12efec0ca4e45b7899d49b2c8258fc993f486509d7f94b52c4a29f8a1053fb5c3d8b9038` |
| TLSH | `T193C329A9F890DE52C6D526B6FB4E418C33231778C3DE7106CE149E3467FB95A0A3E942` |
| SSDEEP | `3072:QuIBvPRfsNDUxMa3tIDrcYEEUIAyMW0NwhBigpmqzWNiF+WOur5mf1Dl:QJ5GytercYEEUIAyMWGwiOmqzpJNm95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_f78648c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f78648c17aa133d312e0255869f5b35aae1ca7674349e8a050df2da8c9e25d9a"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:24"
  condition:
    hash.sha256(0, filesize) == "f78648c17aa133d312e0255869f5b35aae1ca7674349e8a050df2da8c9e25d9a"
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
 * Generated: 2026-07-21T03:51:16.640638+00:00
 */

rule MalwareBazaar_Mirai_001_f76ea26f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f76ea26f6031ebd63e849b1c41bf6a6255d8291e47482617557fd73154ce445f"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-21 03:43:52"
  condition:
    hash.sha256(0, filesize) == "f76ea26f6031ebd63e849b1c41bf6a6255d8291e47482617557fd73154ce445f"
}

rule MalwareBazaar_Mirai_002_9650b84c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9650b84c44403decb656beab529c70fc1ec02bafa9d70f7694c381998bbea22d"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-07-21 03:42:53"
  condition:
    hash.sha256(0, filesize) == "9650b84c44403decb656beab529c70fc1ec02bafa9d70f7694c381998bbea22d"
}

rule MalwareBazaar_unknown_003_108ef7e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc"
    family = "unknown"
    file_name = "wmaines_rmm_v2.5.0.67_oid3f4ebaba-6585-48d9-82be-4e2f3124e8b3_bid8etMwZceBUaX5sZKZactsw.exe"
    file_type = "exe"
    first_seen = "2026-07-21 03:37:21"
  condition:
    hash.sha256(0, filesize) == "108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc"
}

rule MalwareBazaar_unknown_004_62829325
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "628293254de28ceb33d8905f928da292d0e31897a8825bbccaefed10536b0a9e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 02:52:09"
  condition:
    hash.sha256(0, filesize) == "628293254de28ceb33d8905f928da292d0e31897a8825bbccaefed10536b0a9e"
}

rule MalwareBazaar_unknown_005_12552a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12552a110d5bcb5f593c40df2e78ce7253cc6103b245adb3029b15d44026f3c0"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-21 02:24:48"
  condition:
    hash.sha256(0, filesize) == "12552a110d5bcb5f593c40df2e78ce7253cc6103b245adb3029b15d44026f3c0"
}

rule MalwareBazaar_unknown_006_44f4620c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44f4620c1f239c8abba7f0b04b63f2238ed917f1285ebc416d2c2d21adb3a6cf"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-21 02:24:37"
  condition:
    hash.sha256(0, filesize) == "44f4620c1f239c8abba7f0b04b63f2238ed917f1285ebc416d2c2d21adb3a6cf"
}

rule MalwareBazaar_unknown_007_db99e7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db99e7a9d7ba73fbdcf2e0c9d6a7efb496beb29f87d00ddccff1825c641d1bf4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-21 02:19:15"
  condition:
    hash.sha256(0, filesize) == "db99e7a9d7ba73fbdcf2e0c9d6a7efb496beb29f87d00ddccff1825c641d1bf4"
}

rule MalwareBazaar_unknown_008_dc745c18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc745c186d00780cc85dd82adf4186441935ebc6547e375d778eaffb5dbe9305"
    family = "unknown"
    file_name = "softinst.873360017.msi"
    file_type = "msi"
    first_seen = "2026-07-21 02:16:36"
  condition:
    hash.sha256(0, filesize) == "dc745c186d00780cc85dd82adf4186441935ebc6547e375d778eaffb5dbe9305"
}

rule MalwareBazaar_unknown_009_941bae04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "941bae04b8307eff2faa47f60c59298717d218e06c4e716ff576dc9cf0363ddb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-21 01:52:36"
  condition:
    hash.sha256(0, filesize) == "941bae04b8307eff2faa47f60c59298717d218e06c4e716ff576dc9cf0363ddb"
}

rule MalwareBazaar_unknown_010_26dfbed7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26dfbed73c43b51a8b0b2136e35f78bd987aff9fd163c5c7abaeca4ce639ae17"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 01:52:08"
  condition:
    hash.sha256(0, filesize) == "26dfbed73c43b51a8b0b2136e35f78bd987aff9fd163c5c7abaeca4ce639ae17"
}

rule MalwareBazaar_unknown_011_238938a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "238938a735d49263fa104db44584978eb478d6fee9617881c60762f621715325"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-21 01:45:24"
  condition:
    hash.sha256(0, filesize) == "238938a735d49263fa104db44584978eb478d6fee9617881c60762f621715325"
}

rule MalwareBazaar_unknown_012_d321b7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d321b7d4712744fe03084d7a54f53836279e19b9c35426990057991146e7d9f1"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-21 01:13:11"
  condition:
    hash.sha256(0, filesize) == "d321b7d4712744fe03084d7a54f53836279e19b9c35426990057991146e7d9f1"
}

rule MalwareBazaar_unknown_013_901ad9c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "901ad9c29b0944a6af9642c4021c80f7959c8d31c7fb7b9a6216e17d12244541"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-21 01:08:59"
  condition:
    hash.sha256(0, filesize) == "901ad9c29b0944a6af9642c4021c80f7959c8d31c7fb7b9a6216e17d12244541"
}

rule MalwareBazaar_unknown_014_e296f651
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e296f65108930c6e5d0fcd0ecd4654099dae322ce118e25fbfe01250dc8e1c29"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 00:52:08"
  condition:
    hash.sha256(0, filesize) == "e296f65108930c6e5d0fcd0ecd4654099dae322ce118e25fbfe01250dc8e1c29"
}

rule MalwareBazaar_unknown_015_748f3c27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "748f3c2705750d776056a58fff76a54251d252f537b5000d54aab46ab4f56db2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-21 00:52:05"
  condition:
    hash.sha256(0, filesize) == "748f3c2705750d776056a58fff76a54251d252f537b5000d54aab46ab4f56db2"
}

rule MalwareBazaar_unknown_016_44135580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4413558056659da02a67fb77b30fd223e090468899ba2714ebdf6e0a9b9ff9bc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-21 00:30:48"
  condition:
    hash.sha256(0, filesize) == "4413558056659da02a67fb77b30fd223e090468899ba2714ebdf6e0a9b9ff9bc"
}

rule MalwareBazaar_Mirai_017_847866fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847866fd99c7898e27069e3f0dce04c6e5e39ba51bb2a86ccc086d51b4320b95"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-21 00:26:15"
  condition:
    hash.sha256(0, filesize) == "847866fd99c7898e27069e3f0dce04c6e5e39ba51bb2a86ccc086d51b4320b95"
}

rule MalwareBazaar_Mirai_018_3e94cbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e94cbf359f2bef4c8ef6dd71108455108c00c3b917aadb2015c176d60bbdd9d"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-21 00:24:37"
  condition:
    hash.sha256(0, filesize) == "3e94cbf359f2bef4c8ef6dd71108455108c00c3b917aadb2015c176d60bbdd9d"
}

rule MalwareBazaar_Mirai_019_b48be96d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48be96d4178766e340c72991622f74f66b10791742edc9e326ea77812261288"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.sh4"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:48"
  condition:
    hash.sha256(0, filesize) == "b48be96d4178766e340c72991622f74f66b10791742edc9e326ea77812261288"
}

rule MalwareBazaar_Mirai_020_ac932425
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac93242580236d6e3be41e03c6dd00aee95c9b0921cfa9356dc307b5006f9e69"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:47"
  condition:
    hash.sha256(0, filesize) == "ac93242580236d6e3be41e03c6dd00aee95c9b0921cfa9356dc307b5006f9e69"
}

rule MalwareBazaar_Mirai_021_0ba8684a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ba8684a96ed25751f1cee251f68437c9030725f8bbebb0bbedad4454ffdea34"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm5"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:45"
  condition:
    hash.sha256(0, filesize) == "0ba8684a96ed25751f1cee251f68437c9030725f8bbebb0bbedad4454ffdea34"
}

rule MalwareBazaar_Mirai_022_12f1d677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f1d677a4f4dd24a1f21cb02d9dfd0eb5cdc58c69024efe3eb66ebd1fa3562a"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm7"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:44"
  condition:
    hash.sha256(0, filesize) == "12f1d677a4f4dd24a1f21cb02d9dfd0eb5cdc58c69024efe3eb66ebd1fa3562a"
}

rule MalwareBazaar_Mirai_023_f56343d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f56343d2afffab61cfb5eca2a2b47a133a1f936843eba0d061f0ddaaf89d26ce"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.x86"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:42"
  condition:
    hash.sha256(0, filesize) == "f56343d2afffab61cfb5eca2a2b47a133a1f936843eba0d061f0ddaaf89d26ce"
}

rule MalwareBazaar_Mirai_024_6497eed5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6497eed5be632771c4022363b485c448a55912ca75d08ba5213581b4811f7e43"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.spc"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:41"
  condition:
    hash.sha256(0, filesize) == "6497eed5be632771c4022363b485c448a55912ca75d08ba5213581b4811f7e43"
}

rule MalwareBazaar_Mirai_025_daa5fdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daa5fdf5ba5227719e4435960cb10a339634c8406c71b09ce9eb7f5bc53cfe3d"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.m68k"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:40"
  condition:
    hash.sha256(0, filesize) == "daa5fdf5ba5227719e4435960cb10a339634c8406c71b09ce9eb7f5bc53cfe3d"
}

rule MalwareBazaar_Mirai_026_488a3dc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "488a3dc8fc944a607f365a5b609dfd285d0f881b6446be3553c254617579bac1"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.ppc"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:38"
  condition:
    hash.sha256(0, filesize) == "488a3dc8fc944a607f365a5b609dfd285d0f881b6446be3553c254617579bac1"
}

rule MalwareBazaar_Mirai_027_49665430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49665430bea49701da165dbadd6b8f99bde4d804fcae784072d2460c3c7d5b1e"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.arm6"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:37"
  condition:
    hash.sha256(0, filesize) == "49665430bea49701da165dbadd6b8f99bde4d804fcae784072d2460c3c7d5b1e"
}

rule MalwareBazaar_unknown_028_4e92f193
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e92f1931a87c22e5544e6dae88a71ecdeb4e30251d71826df991fa3bbcf76f8"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-21 00:20:36"
  condition:
    hash.sha256(0, filesize) == "4e92f1931a87c22e5544e6dae88a71ecdeb4e30251d71826df991fa3bbcf76f8"
}

rule MalwareBazaar_Mirai_029_790788c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "790788c47dd14f4f25ab7befca04cdccf78b3071ac706f9ec3333e2faaebeeef"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.x86_64"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:34"
  condition:
    hash.sha256(0, filesize) == "790788c47dd14f4f25ab7befca04cdccf78b3071ac706f9ec3333e2faaebeeef"
}

rule MalwareBazaar_Mirai_030_b6391baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6391baa6d58d96c8a339e98a60371e646d6a558b50cecd8bf42047dc61127a0"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.mpsl"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:33"
  condition:
    hash.sha256(0, filesize) == "b6391baa6d58d96c8a339e98a60371e646d6a558b50cecd8bf42047dc61127a0"
}

rule MalwareBazaar_Mirai_031_7011eceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7011eceba8cf057f0103c1d44515be4211c1a56da468ac2ee3e0c12719c555b8"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.mips"
    file_type = "elf"
    first_seen = "2026-07-21 00:20:32"
  condition:
    hash.sha256(0, filesize) == "7011eceba8cf057f0103c1d44515be4211c1a56da468ac2ee3e0c12719c555b8"
}

rule MalwareBazaar_Mirai_032_7694570b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7694570bd0ddd16c6e60fbadd1d32a78c29944a1fa0cc19eacaa819d65654c05"
    family = "Mirai"
    file_name = "nullnet.mpsl"
    file_type = "elf"
    first_seen = "2026-07-21 00:18:46"
  condition:
    hash.sha256(0, filesize) == "7694570bd0ddd16c6e60fbadd1d32a78c29944a1fa0cc19eacaa819d65654c05"
}

rule MalwareBazaar_Mirai_033_98c21848
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98c21848798bd3259b4eefe0b455d510f6e481c476882f03708cefafdbb10e54"
    family = "Mirai"
    file_name = "nullnet.spc"
    file_type = "elf"
    first_seen = "2026-07-21 00:18:43"
  condition:
    hash.sha256(0, filesize) == "98c21848798bd3259b4eefe0b455d510f6e481c476882f03708cefafdbb10e54"
}

rule MalwareBazaar_unknown_034_f9b929cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9b929cf16581d825fe88d676b5114e50d1b77daa4488d15ab0e3fd71bfb1796"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-21 00:18:42"
  condition:
    hash.sha256(0, filesize) == "f9b929cf16581d825fe88d676b5114e50d1b77daa4488d15ab0e3fd71bfb1796"
}

rule MalwareBazaar_unknown_035_df8048b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df8048b1c8753f67cb7eaf49032434fcda89b3a5fb581ba1b002efe9a66098b5"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-21 00:18:41"
  condition:
    hash.sha256(0, filesize) == "df8048b1c8753f67cb7eaf49032434fcda89b3a5fb581ba1b002efe9a66098b5"
}

rule MalwareBazaar_Mirai_036_f7fc5c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7fc5c3daba8d328b54ee98c69b1e28c78a7f3d7c25485db40f85b6fd49071b2"
    family = "Mirai"
    file_name = "nullnet.ppc"
    file_type = "elf"
    first_seen = "2026-07-21 00:07:46"
  condition:
    hash.sha256(0, filesize) == "f7fc5c3daba8d328b54ee98c69b1e28c78a7f3d7c25485db40f85b6fd49071b2"
}

rule MalwareBazaar_Mirai_037_001b17ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "001b17ec7703e99a383799c633408b2315e9394bc1af1b924721af640b628a74"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-21 00:01:55"
  condition:
    hash.sha256(0, filesize) == "001b17ec7703e99a383799c633408b2315e9394bc1af1b924721af640b628a74"
}

rule MalwareBazaar_unknown_038_584bd68a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "584bd68a9102cbaa179b916832ad5827c9e9d5b1af17f8570e54134c7a3db0d7"
    family = "unknown"
    file_name = "nFedex_G68389B54.iso"
    file_type = "iso"
    first_seen = "2026-07-21 00:00:17"
  condition:
    hash.sha256(0, filesize) == "584bd68a9102cbaa179b916832ad5827c9e9d5b1af17f8570e54134c7a3db0d7"
}

rule MalwareBazaar_Mirai_039_65c8a814
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65c8a814d54394758ae4cff4318466c127117f46d22514a2ebb56610c8bf6dcd"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-20 23:59:54"
  condition:
    hash.sha256(0, filesize) == "65c8a814d54394758ae4cff4318466c127117f46d22514a2ebb56610c8bf6dcd"
}

rule MalwareBazaar_Mirai_040_e3950c8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3950c8a20d06ad26ea0b0b9662479bab92ff2459a92eccf80e9546b10da793a"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-20 23:53:44"
  condition:
    hash.sha256(0, filesize) == "e3950c8a20d06ad26ea0b0b9662479bab92ff2459a92eccf80e9546b10da793a"
}

rule MalwareBazaar_Mirai_041_a5892c75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5892c7527aceab6f01efb2e266fce135dc6701e3d34cb5f56b857bb28aed901"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-20 23:52:30"
  condition:
    hash.sha256(0, filesize) == "a5892c7527aceab6f01efb2e266fce135dc6701e3d34cb5f56b857bb28aed901"
}

rule MalwareBazaar_unknown_042_f42cd03d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42cd03d9db9469b3cc83f8a3ef36a9e72211fb6b481456b1e199563a523dc87"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 23:52:09"
  condition:
    hash.sha256(0, filesize) == "f42cd03d9db9469b3cc83f8a3ef36a9e72211fb6b481456b1e199563a523dc87"
}

rule MalwareBazaar_unknown_043_cd4498d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4498d39e8126c9779a7d55fc860b8e06d1875d8f6add1ed208698c00c03811"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 23:43:47"
  condition:
    hash.sha256(0, filesize) == "cd4498d39e8126c9779a7d55fc860b8e06d1875d8f6add1ed208698c00c03811"
}

rule MalwareBazaar_unknown_044_8c70ae6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c70ae6d0965351ec8417ed37bba85dd58b05afae292cf932efeb4fcc5c7b331"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 22:52:09"
  condition:
    hash.sha256(0, filesize) == "8c70ae6d0965351ec8417ed37bba85dd58b05afae292cf932efeb4fcc5c7b331"
}

rule MalwareBazaar_Prometei_045_6aae69fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099"
    family = "Prometei"
    file_name = "6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099"
    file_type = "elf"
    first_seen = "2026-07-20 22:48:04"
  condition:
    hash.sha256(0, filesize) == "6aae69fdd57ce162f19b5ecd8ffc24f1ceac61281a88e610f6813b7db9195099"
}

rule MalwareBazaar_unknown_046_bca78e47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca78e472cdf94c16fd67cdf2894d7286c17b370007878b988b9a9f9705f99d5"
    family = "unknown"
    file_name = "yuanbao.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:38:46"
  condition:
    hash.sha256(0, filesize) == "bca78e472cdf94c16fd67cdf2894d7286c17b370007878b988b9a9f9705f99d5"
}

rule MalwareBazaar_Gh0stRAT_047_96c0911c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96c0911c225219cfd380076f5196d7ee87c617cddb968d3d465122473e20d6fb"
    family = "Gh0stRAT"
    file_name = "yuanbao.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:38:00"
  condition:
    hash.sha256(0, filesize) == "96c0911c225219cfd380076f5196d7ee87c617cddb968d3d465122473e20d6fb"
}

rule MalwareBazaar_ValleyRAT_048_63522452
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63522452b1ed07e4f33376b0b8c85a4045e85594c3e7b03354afd985b691522f"
    family = "ValleyRAT"
    file_name = "2026.07.20裁员名单及补偿方案_SUET.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:37:02"
  condition:
    hash.sha256(0, filesize) == "63522452b1ed07e4f33376b0b8c85a4045e85594c3e7b03354afd985b691522f"
}

rule MalwareBazaar_NanoCore_049_d96fc5f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96fc5f700b931e47dee0b979f267ac803f02a6726a4cb6464daf7dd17bc17fe"
    family = "NanoCore"
    file_name = "4357b7160b0765b1714a08aeb54c2dc8.exe"
    file_type = "exe"
    first_seen = "2026-07-20 22:30:05"
  condition:
    hash.sha256(0, filesize) == "d96fc5f700b931e47dee0b979f267ac803f02a6726a4cb6464daf7dd17bc17fe"
}

rule MalwareBazaar_unknown_050_0e1ca1c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e1ca1c207eba5bc7b8fb7fb14698999fe9e4189d56ca5b88f86dacfbf409ddb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 22:19:52"
  condition:
    hash.sha256(0, filesize) == "0e1ca1c207eba5bc7b8fb7fb14698999fe9e4189d56ca5b88f86dacfbf409ddb"
}

rule MalwareBazaar_unknown_051_6a25ea3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a25ea3dc7e86e1d0bdcf0becbfb120b4d2b36c38cb63e5106ee7e8ddea1cf7c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 21:52:11"
  condition:
    hash.sha256(0, filesize) == "6a25ea3dc7e86e1d0bdcf0becbfb120b4d2b36c38cb63e5106ee7e8ddea1cf7c"
}

rule MalwareBazaar_RemusStealer_052_b66775e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66775e5a6169599519e5b3e035bea6ca2824e14ad59662b9d43d356ba6b3c4d"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-20 21:52:07"
  condition:
    hash.sha256(0, filesize) == "b66775e5a6169599519e5b3e035bea6ca2824e14ad59662b9d43d356ba6b3c4d"
}

rule MalwareBazaar_unknown_053_e1f122c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1f122c6154e1ec48b09f423d59b2f007751bb70f83fb37967d8263526045358"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 21:40:32"
  condition:
    hash.sha256(0, filesize) == "e1f122c6154e1ec48b09f423d59b2f007751bb70f83fb37967d8263526045358"
}

rule MalwareBazaar_unknown_054_1551ea45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1551ea450f0da4f6e6494b4fab62a7637f7ec5d1b7d6d47b032314ab5e761717"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-20 20:56:41"
  condition:
    hash.sha256(0, filesize) == "1551ea450f0da4f6e6494b4fab62a7637f7ec5d1b7d6d47b032314ab5e761717"
}

rule MalwareBazaar_unknown_055_53b2d24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53b2d24c9aefe01a768f6e2c637ab9fd56dcede852925cec18eccae58dfecec7"
    family = "unknown"
    file_name = "YZi Labs - Audit Confirmation Form - June 30 2026.docx.scpt"
    file_type = "unknown"
    first_seen = "2026-07-20 20:54:39"
  condition:
    hash.sha256(0, filesize) == "53b2d24c9aefe01a768f6e2c637ab9fd56dcede852925cec18eccae58dfecec7"
}

rule MalwareBazaar_unknown_056_7391ec43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7391ec43b2e0621c8c6472b686b900722a4f22ca037b3ebd0ade5a86a880332b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 20:52:24"
  condition:
    hash.sha256(0, filesize) == "7391ec43b2e0621c8c6472b686b900722a4f22ca037b3ebd0ade5a86a880332b"
}

rule MalwareBazaar_RemusStealer_057_f2796171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2796171d51454389ccb9d26a65794a030b1aaa80dbcb79a99153443c3151e40"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-20 20:52:07"
  condition:
    hash.sha256(0, filesize) == "f2796171d51454389ccb9d26a65794a030b1aaa80dbcb79a99153443c3151e40"
}

rule MalwareBazaar_Mirai_058_a927fe31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a927fe3149e454d08a3a87131ced2a785da121fa879566dbb274aa29d7732eb6"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 20:49:36"
  condition:
    hash.sha256(0, filesize) == "a927fe3149e454d08a3a87131ced2a785da121fa879566dbb274aa29d7732eb6"
}

rule MalwareBazaar_Mirai_059_c67577c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c67577c4771d12285ea8fdca4dc7700f75861f8f74f82f8126c49e86a4b40044"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 20:48:39"
  condition:
    hash.sha256(0, filesize) == "c67577c4771d12285ea8fdca4dc7700f75861f8f74f82f8126c49e86a4b40044"
}

rule MalwareBazaar_unknown_060_0934db4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0934db4eb30297c9815b0eefed038850d56b721cca115fc6881f4b870df41753"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-20 20:42:34"
  condition:
    hash.sha256(0, filesize) == "0934db4eb30297c9815b0eefed038850d56b721cca115fc6881f4b870df41753"
}

rule MalwareBazaar_Mirai_061_40df91b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40df91b940eea28d176edccda20a8e2e4e281eb531254486d4c69af08dd29842"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 20:39:35"
  condition:
    hash.sha256(0, filesize) == "40df91b940eea28d176edccda20a8e2e4e281eb531254486d4c69af08dd29842"
}

rule MalwareBazaar_Mirai_062_90ac8ec4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90ac8ec4e015343f2f175d29a2e147109a76fd65582dfa9cad80144826336872"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 20:39:32"
  condition:
    hash.sha256(0, filesize) == "90ac8ec4e015343f2f175d29a2e147109a76fd65582dfa9cad80144826336872"
}

rule MalwareBazaar_Mirai_063_3f509b84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f509b8445f1b263397f3d531f478aeb9b046e0ab7582549a622e912a7161fda"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 20:38:37"
  condition:
    hash.sha256(0, filesize) == "3f509b8445f1b263397f3d531f478aeb9b046e0ab7582549a622e912a7161fda"
}

rule MalwareBazaar_Mirai_064_9354ba87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9354ba8758ad0702251b2ea6dfa82cb7ba34c0e7f32e5cfc83aed0baebb3c456"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 20:38:36"
  condition:
    hash.sha256(0, filesize) == "9354ba8758ad0702251b2ea6dfa82cb7ba34c0e7f32e5cfc83aed0baebb3c456"
}

rule MalwareBazaar_Mirai_065_b6819af7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6819af7882a880ab0119b79fa068177570e53cf205653e4091bdfafc7ccf8b8"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 20:28:46"
  condition:
    hash.sha256(0, filesize) == "b6819af7882a880ab0119b79fa068177570e53cf205653e4091bdfafc7ccf8b8"
}

rule MalwareBazaar_unknown_066_774813aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774813aa1ca069bf99771e37766b073e569e7cfb5056593126598f5fae343661"
    family = "unknown"
    file_name = "busywget.sh"
    file_type = "sh"
    first_seen = "2026-07-20 20:26:47"
  condition:
    hash.sha256(0, filesize) == "774813aa1ca069bf99771e37766b073e569e7cfb5056593126598f5fae343661"
}

rule MalwareBazaar_unknown_067_29b4af86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2"
    family = "unknown"
    file_name = "29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2"
    file_type = "unknown"
    first_seen = "2026-07-20 20:19:46"
  condition:
    hash.sha256(0, filesize) == "29b4af860c1a6f86e52cefd4c75900efe9c0262f96949a07431f9e74dbbe7ff2"
}

rule MalwareBazaar_Mirai_068_72a5a6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72a5a6dd913263a9773df35c1ae3c5d0fea06bb7848c9ecf91c1ea8eca8f9979"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 20:15:53"
  condition:
    hash.sha256(0, filesize) == "72a5a6dd913263a9773df35c1ae3c5d0fea06bb7848c9ecf91c1ea8eca8f9979"
}

rule MalwareBazaar_unknown_069_4dc8b56b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dc8b56b03e7c8cf3b12bf57c07e0bb9a61ecd18615ed60e2f0124ad9b4e9061"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 20:15:48"
  condition:
    hash.sha256(0, filesize) == "4dc8b56b03e7c8cf3b12bf57c07e0bb9a61ecd18615ed60e2f0124ad9b4e9061"
}

rule MalwareBazaar_Mirai_070_7ac23035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac23035d89498bc3d3b148d726bb072a07f7e579b55618ad5f686ef7048ade1"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 20:14:59"
  condition:
    hash.sha256(0, filesize) == "7ac23035d89498bc3d3b148d726bb072a07f7e579b55618ad5f686ef7048ade1"
}

rule MalwareBazaar_unknown_071_05feafe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05feafe05fedb138116489ceca8a84b302ed59e2f3d18daa9527b057aa485c9a"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-20 19:59:59"
  condition:
    hash.sha256(0, filesize) == "05feafe05fedb138116489ceca8a84b302ed59e2f3d18daa9527b057aa485c9a"
}

rule MalwareBazaar_unknown_072_6ef76a3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ef76a3b50c9f70408e74e4c15d986f94979711d35f3f6744d1ab61387214eb6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-20 19:52:09"
  condition:
    hash.sha256(0, filesize) == "6ef76a3b50c9f70408e74e4c15d986f94979711d35f3f6744d1ab61387214eb6"
}

rule MalwareBazaar_unknown_073_84d07f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d07f96725bc87d56f68936dd3879ffe67f1f8d694be9fbc4edd4a6d9a44615"
    family = "unknown"
    file_name = "verification.ps1"
    file_type = "ps1"
    first_seen = "2026-07-20 19:46:08"
  condition:
    hash.sha256(0, filesize) == "84d07f96725bc87d56f68936dd3879ffe67f1f8d694be9fbc4edd4a6d9a44615"
}

rule MalwareBazaar_Mirai_074_2e086924
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e086924a7835d4679749992f6b684ccf2fa5ab7f33fa69201b22ccf1f98571c"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:40:52"
  condition:
    hash.sha256(0, filesize) == "2e086924a7835d4679749992f6b684ccf2fa5ab7f33fa69201b22ccf1f98571c"
}

rule MalwareBazaar_Mirai_075_c165527a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c165527a2aa356d02f68fd695fbfe5ae9170eb8b6862e48cf9758e0ec6eebe31"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:39:58"
  condition:
    hash.sha256(0, filesize) == "c165527a2aa356d02f68fd695fbfe5ae9170eb8b6862e48cf9758e0ec6eebe31"
}

rule MalwareBazaar_Gh0stRAT_076_af9a6dac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af9a6dacb2a9618866cf398d615b2fe1c1c98ec7254d38a01c7c2d6869821bbe"
    family = "Gh0stRAT"
    file_name = "moshou-xinshouhezi.zip"
    file_type = "zip"
    first_seen = "2026-07-20 19:38:23"
  condition:
    hash.sha256(0, filesize) == "af9a6dacb2a9618866cf398d615b2fe1c1c98ec7254d38a01c7c2d6869821bbe"
}

rule MalwareBazaar_Mirai_077_cdf7dbac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdf7dbac5c8ca636350541007bf67ac05634ef36dbf64ffd7c73dbc6db5bb280"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 19:37:43"
  condition:
    hash.sha256(0, filesize) == "cdf7dbac5c8ca636350541007bf67ac05634ef36dbf64ffd7c73dbc6db5bb280"
}

rule MalwareBazaar_Mirai_078_bce3c7ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bce3c7ad26433b03c0aeb8d987e9b6b889582fe8ef870949329abfaa175c0e81"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-20 19:35:37"
  condition:
    hash.sha256(0, filesize) == "bce3c7ad26433b03c0aeb8d987e9b6b889582fe8ef870949329abfaa175c0e81"
}

rule MalwareBazaar_Mirai_079_17d1b0c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17d1b0c433da78f9a1de8e1ebb04e3174961f8b97aa5d489b21f28dec1c2ac15"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-07-20 19:34:35"
  condition:
    hash.sha256(0, filesize) == "17d1b0c433da78f9a1de8e1ebb04e3174961f8b97aa5d489b21f28dec1c2ac15"
}

rule MalwareBazaar_Mirai_080_f2938a78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2938a785b50c89b61abcfe405a5ecececba42d259eba1ccceed5e32821da33d"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-20 19:34:33"
  condition:
    hash.sha256(0, filesize) == "f2938a785b50c89b61abcfe405a5ecececba42d259eba1ccceed5e32821da33d"
}

rule MalwareBazaar_Mirai_081_83fee47d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83fee47d6e11339cbd8af4546a6db2e7b4b29387533f81e7c082d44cafe3ed56"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-20 19:22:26"
  condition:
    hash.sha256(0, filesize) == "83fee47d6e11339cbd8af4546a6db2e7b4b29387533f81e7c082d44cafe3ed56"
}

rule MalwareBazaar_Mirai_082_e1022982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e10229824df64c0d22d67af78f9be8649429cdc3858fc905aba4bb57a98acb3f"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-07-20 19:20:11"
  condition:
    hash.sha256(0, filesize) == "e10229824df64c0d22d67af78f9be8649429cdc3858fc905aba4bb57a98acb3f"
}

rule MalwareBazaar_unknown_083_67229a50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67229a5054aa6e8c7f7f05bdff86da66b8e54363a455a8f902141ed0b39fcdec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-20 19:17:28"
  condition:
    hash.sha256(0, filesize) == "67229a5054aa6e8c7f7f05bdff86da66b8e54363a455a8f902141ed0b39fcdec"
}

rule MalwareBazaar_Mirai_084_baf0843b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf0843bbc852500c72e11c41c0c279a5d94b1b395ebe6403ed4e68473caac20"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:49"
  condition:
    hash.sha256(0, filesize) == "baf0843bbc852500c72e11c41c0c279a5d94b1b395ebe6403ed4e68473caac20"
}

rule MalwareBazaar_Mirai_085_16e1cd6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e1cd6a877ff9c0c0c4fbe3bb87a6077ca30dbe9443b8096456a7ad4dc63955"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:47"
  condition:
    hash.sha256(0, filesize) == "16e1cd6a877ff9c0c0c4fbe3bb87a6077ca30dbe9443b8096456a7ad4dc63955"
}

rule MalwareBazaar_Mirai_086_973f0b79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "973f0b790ce63155e93a735c98334879ffcda03fdd4976afc9e18fefa8af854f"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:44"
  condition:
    hash.sha256(0, filesize) == "973f0b790ce63155e93a735c98334879ffcda03fdd4976afc9e18fefa8af854f"
}

rule MalwareBazaar_Mirai_087_c1194291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1194291bfd88db485cf45f31cb17a04b261de1455047a4a6e330b26fb87877a"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:39"
  condition:
    hash.sha256(0, filesize) == "c1194291bfd88db485cf45f31cb17a04b261de1455047a4a6e330b26fb87877a"
}

rule MalwareBazaar_Mirai_088_b96fe3c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96fe3c442ff0efc544510eb8c724be73a2eb7f0c21f21b6ba68e678778d129d"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:10"
  condition:
    hash.sha256(0, filesize) == "b96fe3c442ff0efc544510eb8c724be73a2eb7f0c21f21b6ba68e678778d129d"
}

rule MalwareBazaar_Mirai_089_0e2f8842
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e2f88421bec2bf2fb22c26c8bd5b10469921fc66310b01b39937487d5a1904f"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:03"
  condition:
    hash.sha256(0, filesize) == "0e2f88421bec2bf2fb22c26c8bd5b10469921fc66310b01b39937487d5a1904f"
}

rule MalwareBazaar_Mirai_090_9880eb40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9880eb40dbffc85f31d411dc5f28344ef101494dd2944a87bfa1f87a917b83bb"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-20 19:14:00"
  condition:
    hash.sha256(0, filesize) == "9880eb40dbffc85f31d411dc5f28344ef101494dd2944a87bfa1f87a917b83bb"
}

rule MalwareBazaar_Mirai_091_02142753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021427534dbf7d135a102de94627a2809ea47ed6dd9753116999aa50989771c9"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:12"
  condition:
    hash.sha256(0, filesize) == "021427534dbf7d135a102de94627a2809ea47ed6dd9753116999aa50989771c9"
}

rule MalwareBazaar_Mirai_092_90b98753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90b9875329d3272f60376d93c7096818da5264bb7f264c2f76ec7b528be69c87"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:11"
  condition:
    hash.sha256(0, filesize) == "90b9875329d3272f60376d93c7096818da5264bb7f264c2f76ec7b528be69c87"
}

rule MalwareBazaar_Mirai_093_e706cc6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e706cc6ce9f500e179b0cdebca1f60462591f4d67a54cc785c2217d3665100fd"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:09"
  condition:
    hash.sha256(0, filesize) == "e706cc6ce9f500e179b0cdebca1f60462591f4d67a54cc785c2217d3665100fd"
}

rule MalwareBazaar_Mirai_094_451e6277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451e62772cb780fa8cd93a36f5041c349d62dfb83e6c9879c082050b55a5b444"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-20 19:13:08"
  condition:
    hash.sha256(0, filesize) == "451e62772cb780fa8cd93a36f5041c349d62dfb83e6c9879c082050b55a5b444"
}

rule MalwareBazaar_Mirai_095_53f741e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53f741e54d11c319bcf5a268a5325208ec99cd2706c1932f9f6e3193044f871a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:57"
  condition:
    hash.sha256(0, filesize) == "53f741e54d11c319bcf5a268a5325208ec99cd2706c1932f9f6e3193044f871a"
}

rule MalwareBazaar_Mirai_096_ff363cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff363cb6f29a269fc7763c2a5ea564b0d45ecf64b422d024bcf0912877ed075f"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:53"
  condition:
    hash.sha256(0, filesize) == "ff363cb6f29a269fc7763c2a5ea564b0d45ecf64b422d024bcf0912877ed075f"
}

rule MalwareBazaar_Mirai_097_8e5fe294
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e5fe294c314bb1c2dbfa2ff6225b79380a5494fa70ecb1b8f1e6cf725a61427"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:50"
  condition:
    hash.sha256(0, filesize) == "8e5fe294c314bb1c2dbfa2ff6225b79380a5494fa70ecb1b8f1e6cf725a61427"
}

rule MalwareBazaar_Mirai_098_993012e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "993012e0659b402b9ad154ffbbc6d7ba0c69dc79fcf63cc23886ddd6286e79e4"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:46"
  condition:
    hash.sha256(0, filesize) == "993012e0659b402b9ad154ffbbc6d7ba0c69dc79fcf63cc23886ddd6286e79e4"
}

rule MalwareBazaar_Mirai_099_1684d94a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1684d94aee96c6c48111d57b4c1999cad4f4c490091a6b974492bef7a4519109"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:34"
  condition:
    hash.sha256(0, filesize) == "1684d94aee96c6c48111d57b4c1999cad4f4c490091a6b974492bef7a4519109"
}

rule MalwareBazaar_Mirai_100_f78648c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f78648c17aa133d312e0255869f5b35aae1ca7674349e8a050df2da8c9e25d9a"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-20 19:11:24"
  condition:
    hash.sha256(0, filesize) == "f78648c17aa133d312e0255869f5b35aae1ca7674349e8a050df2da8c9e25d9a"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

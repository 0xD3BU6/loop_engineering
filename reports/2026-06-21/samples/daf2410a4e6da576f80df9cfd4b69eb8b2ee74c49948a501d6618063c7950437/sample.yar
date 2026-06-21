import "hash"

rule Single_Sample_Static_daf2410a4e6da576
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
    md5 = "f749306e539eab248f698468a5ffc7f0"
    sha1 = "d7bbb24c3a449bbdf9031fb92753b2d96a68a587"
    file_magic = "source-like text"
    malwarebazaar_family = "RemcosRAT"
  strings:
    $placeholder = "no_selected_static_strings"
  condition:
    hash.sha256(0, filesize) == "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "javascript"
    analysis = "static text only; sample not executed"
  strings:
    $shell_execution_01 = /powershell(?:\.exe)?/ nocase
    $powershell_cradle_02 = /Invoke-Expression|\bIEX\b/ nocase
    $powershell_cradle_03 = /FromBase64String/ nocase
    $persistence_04 = /Startup/ nocase
  condition:
    any of them
}


rule Single_Sample_Metadata_Network_daf2410a4e6da576
{
  meta:
    source = "loop-engineering single-sample analysis (MalwareBazaar metadata)"
    analysis = "network indicators from submission tags; not statically observed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
  strings:
    $n01 = "46.183.223.7" nocase
    $n02 = "kelvin654.duckdns.org" nocase
  condition:
    any of them
}


rule Single_Sample_Decoded_Payload_daf2410a4e6da576
{
  meta:
    source = "loop-engineering single-sample analysis (decoded payload layers)"
    analysis = "indicators recovered by statically decoding embedded base64; not executed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
  strings:
    $d01 = "http://kickstrean.art/1.jpg" nocase
    $d02 = "https://66.63.170.33/img/1.jpg" nocase
    $d03 = "66.63.170.33" nocase
    $d04 = "kickstrean.art" nocase
  condition:
    any of them
}

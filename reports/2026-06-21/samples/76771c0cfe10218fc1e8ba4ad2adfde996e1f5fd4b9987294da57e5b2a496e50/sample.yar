import "hash"

rule Single_Sample_Static_76771c0cfe10218f
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
    md5 = "0fde1288ef288731aef0855b08be049a"
    sha1 = "827749fd69bc733ab31a00d2376f5fcdcf58968d"
    file_magic = "ff fe 2f 00 2f 00 20 00"
    malwarebazaar_family = "unknown"
  strings:
    $placeholder = "no_selected_static_strings"
  condition:
    hash.sha256(0, filesize) == "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "javascript"
    analysis = "static text only; sample not executed"
  strings:
    $static_placeholder = "no_static_iocs_found"
  condition:
    false
}

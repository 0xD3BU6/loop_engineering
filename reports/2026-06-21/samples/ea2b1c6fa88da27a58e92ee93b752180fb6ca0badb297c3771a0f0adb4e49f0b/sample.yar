import "hash"

rule Single_Sample_Static_ea2b1c6fa88da27a
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b"
    md5 = "e3a12d8a0dc98b06b548a766aa77dc9c"
    sha1 = "adb94417d3aec78b7779161ba359ce18816a3e09"
    file_magic = "script with shebang"
    malwarebazaar_family = "unknown"
  strings:
    $s01 = "# init.sh" nocase
    $s02 = "BASE_URL=\"http://91.239.211.89/bins\"" nocase
    $s03 = "MINER_URL=\"http://91.239.211.89/miner/xmrig\"" nocase
    $s04 = "printf '#!/bin/sh\\necho ok\\n' > \"$testfile\" 2>/dev/null || return 1" nocase
    $s05 = "local guard=\"$miner_dest-guard.sh\"" nocase
    $s06 = "if command -v crontab >/dev/null 2>&1; then" nocase
    $s07 = "(crontab -l 2>/dev/null | grep -v \"$guard\"; echo \"$WATCHDOG_CRON $guard\") | crontab - 2>/dev/null || true" nocase
    $s08 = "log_msg \"init.sh started" nocase
    $s09 = "[ -f /usr/local/lib/libprocesshider.so ] && export LD_PRELOAD=/usr/local/lib/libprocesshider.so" nocase
    $s10 = "if (echo >/dev/tcp/127.0.0.1/$CTRL_PORT) 2>/dev/null; then" nocase
  condition:
    hash.sha256(0, filesize) == "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://91.239.211.89/bins" nocase
    $url_02 = "http://91.239.211.89/miner/xmrig" nocase
    $ip_03 = "127.0.0.1" nocase
    $ip_04 = "91.239.211.89" nocase
    $domain_05 = "guard.sh" nocase
    $domain_06 = "init.sh" nocase
    $domain_07 = "libprocesshider.so" nocase
    $shell_execution_08 = /\/bin\/sh/ nocase
    $persistence_09 = /Startup/ nocase
    $persistence_10 = /crontab/ nocase
    $persistence_11 = /systemd/ nocase
  condition:
    any of them
}

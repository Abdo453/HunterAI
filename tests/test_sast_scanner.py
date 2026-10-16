"""Tests لـ SAST Scanner"""
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sast_scanner.scanner import SASTScanner, SASTFinding


def test_sast_python_sql_injection():
    scanner = SASTScanner()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n')
        tmp = f.name

    findings = scanner.scan_file(tmp)
    os.unlink(tmp)

    sql_findings = [f for f in findings if "sql_injection" in f.rule_id]
    assert len(sql_findings) >= 1
    print("[PASS] sast python sql injection")


def test_sast_javascript_xss():
    scanner = SASTScanner()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write("document.innerHTML = userInput;\n")
        tmp = f.name

    findings = scanner.scan_file(tmp)
    os.unlink(tmp)

    xss_findings = [f for f in findings if "xss" in f.rule_id.lower()]
    assert len(xss_findings) >= 1
    print("[PASS] sast javascript xss")


def test_sast_hardcoded_secret():
    scanner = SASTScanner()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("api_key = 'sk-1234567890abcdef'\n")
        tmp = f.name

    findings = scanner.scan_file(tmp)
    os.unlink(tmp)

    secret_findings = [f for f in findings if "secret" in f.rule_id]
    assert len(secret_findings) >= 1
    print("[PASS] sast hardcoded secret")


def test_sast_directory():
    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmpdir:
        # ملف Python به ثغرة
        with open(os.path.join(tmpdir, "app.py"), "w") as f:
            f.write("os.system(user_input)\n")
        # ملف JavaScript آمن
        with open(os.path.join(tmpdir, "safe.js"), "w") as f:
            f.write("console.log('hello');\n")

        findings = scanner.scan_directory(tmpdir)
        assert len(findings) >= 1
    print("[PASS] sast directory scan")


def test_sast_finding_to_dict():
    finding = SASTFinding(
        record_id="sast_0001",
        rule_id="python.sql_injection",
        rule_message="SQL Injection detected",
        file_path="app.py",
        line_number=5,
        severity="high",
        code_snippet="cursor.execute(query)",
        confidence=0.8,
    )
    d = finding.to_dict()
    assert d["record_id"] == "sast_0001"
    assert d["severity"] == "high"
    print("[PASS] sast finding to_dict")


if __name__ == "__main__":
    test_sast_python_sql_injection()
    test_sast_javascript_xss()
    test_sast_hardcoded_secret()
    test_sast_directory()
    test_sast_finding_to_dict()
    print("\n[INFO] جميع اختبارات SAST Scanner نجحت!")

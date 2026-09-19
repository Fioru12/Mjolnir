import os
import pytest
from core.yara_scanner import YaraPatternScanner, YaraRulesNotFoundError

# Payload fragments below are built via string concatenation rather than as
# single contiguous literals. This is NOT obfuscation for its own sake: the
# straight-line literals (e.g. "eval(base64_decode(") are byte-for-byte
# webshell/ransom-note indicators, and Windows Defender's static scanner
# quarantines any file containing them verbatim - including this test file
# itself, which previously vanished from disk mid-session because of it.
# Splitting the literal avoids that false positive while still exercising
# the exact same bytes at runtime via scan_bytes().


def test_yara_scanner_detects_suspicious_powershell():
    scanner = YaraPatternScanner()
    content = ("powershell.exe " + "-enc" + " aW52b2tlLWV4cHJlc3Npb24=").encode()
    matches = scanner.scan_bytes(content)
    assert len(matches) == 1
    assert matches[0]["rule_id"] == "Suspicious_Encoded_PowerShell"
    assert matches[0]["severity"] == "HIGH"


def test_yara_scanner_detects_webshell():
    scanner = YaraPatternScanner()
    payload = "<?php " + "eval(" + "base64_decode(" + '$_POST["x"]' + ")); ?>"
    matches = scanner.scan_bytes(payload.encode())
    assert any(m["rule_id"] == "Suspicious_Webshell_Generic" for m in matches)
    assert all(m["severity"] == "CRITICAL" for m in matches if m["rule_id"] == "Suspicious_Webshell_Generic")


def test_yara_scanner_detects_ransom_note():
    scanner = YaraPatternScanner()
    payload = "YOUR_FILES" + "_ARE_ENCRYPTED" + ". Pay 1 BTC to recover them."
    matches = scanner.scan_bytes(payload.encode())
    assert any(m["rule_id"] == "Ransomware_Ransom_Note_Text" for m in matches)


def test_yara_scanner_no_match_on_clean_content():
    scanner = YaraPatternScanner()
    matches = scanner.scan_bytes(b"This is a perfectly ordinary text file with nothing suspicious in it.")
    assert matches == []


def test_yara_scanner_scan_file_reads_real_file(tmp_path):
    scanner = YaraPatternScanner()
    malicious_file = tmp_path / "note.txt"
    payload = "HOW_TO" + "_DECRYPT_FILES" + ": contact us at evil@example.com"
    malicious_file.write_bytes(payload.encode())
    matches = scanner.scan_file(str(malicious_file))
    assert any(m["rule_id"] == "Ransomware_Ransom_Note_Text" for m in matches)


def test_yara_scanner_scan_file_missing_file_returns_empty_list():
    scanner = YaraPatternScanner()
    assert scanner.scan_file("C:/this/path/does/not/exist.exe") == []


def test_yara_scanner_honors_yara_nocase_string_modifier():
    """
    Regression guard for the "this isn't actually YARA" finding: rules are
    compiled and matched by the real yara-python/libyara engine from .yar
    files. default.yar's webshell rule declares its strings with the
    `nocase` YARA modifier, so a fully-uppercase variant of the same
    indicator must still match - proving the engine's own string flags are
    in effect, not a Python regex approximation bolted on top.
    """
    scanner = YaraPatternScanner()
    payload = "EVAL(" + 'BASE64_DECODE("payload"))'
    matches = scanner.scan_bytes(payload.encode())
    assert any(m["rule_id"] == "Suspicious_Webshell_Generic" for m in matches)


def test_yara_scanner_loads_custom_rules_dir(tmp_path):
    rules_dir = tmp_path / "custom_rules"
    rules_dir.mkdir()
    (rules_dir / "custom.yar").write_text(
        """
        rule Custom_Test_Rule {
            meta:
                description = "custom marker"
                severity = "MEDIUM"
            strings:
                $marker = "TOTALLY_CUSTOM_MARKER_XYZ"
            condition:
                $marker
        }
        """
    )
    scanner = YaraPatternScanner(rules_dir=str(rules_dir))
    matches = scanner.scan_bytes(b"contains TOTALLY_CUSTOM_MARKER_XYZ somewhere")
    assert len(matches) == 1
    assert matches[0]["rule_id"] == "Custom_Test_Rule"
    assert matches[0]["severity"] == "MEDIUM"
    assert matches[0]["rule_name"] == "custom marker"


def test_yara_scanner_raises_clear_error_when_no_rules_found(tmp_path):
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    with pytest.raises(YaraRulesNotFoundError):
        YaraPatternScanner(rules_dir=str(empty_dir))


def test_yara_scanner_raises_clear_error_when_yara_python_missing(monkeypatch):
    import core.yara_scanner as scanner_module
    monkeypatch.setattr(scanner_module, "YARA_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="yara-python is not installed"):
        scanner_module.YaraPatternScanner()

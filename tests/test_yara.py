import pytest
from core.yara_scanner import YaraPatternScanner

def test_yara_scanner_detects_suspicious_powershell():
    scanner = YaraPatternScanner()
    content = b"powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24="
    matches = scanner.scan_bytes(content)
    assert len(matches) == 1
    assert matches[0]["rule_id"] == "RULE_SUSPICIOUS_POWERSHELL"
    assert matches[0]["severity"] == "HIGH"

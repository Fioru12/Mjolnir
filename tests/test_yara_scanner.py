import pytest
from core.yara_scanner import YaraPatternScanner

def test_yara_scanner_detects_ransomware_note(tmp_path):
    scanner = YaraPatternScanner()
    test_file = tmp_path / "ransom_note.txt"
    test_file.write_bytes(b"ATTENTION! YOUR_FILES_ARE_ENCRYPTED by RagnarLocker.")

    matches = scanner.scan_file(str(test_file))
    assert len(matches) == 1
    assert matches[0]["rule_id"] == "RULE_RANSOMWARE_NOTE"
    assert matches[0]["severity"] == "CRITICAL"

def test_yara_scanner_detects_webshell_pattern():
    scanner = YaraPatternScanner()
    content = b"<?php eval(base64_decode($_POST['cmd'])); ?>"
    matches = scanner.scan_bytes(content)
    assert len(matches) == 1
    assert matches[0]["rule_id"] == "RULE_WEBSHELL_GENERIC"
    assert matches[0]["severity"] == "CRITICAL"

def test_yara_scanner_clean_file():
    scanner = YaraPatternScanner()
    content = b"Hello world, this is a clean log file."
    matches = scanner.scan_bytes(content)
    assert len(matches) == 0

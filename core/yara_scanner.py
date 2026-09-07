import re
import os
from typing import List, Dict, Any, Optional

DEFAULT_RULES = [
    {
        "id": "RULE_WEBSHELL_GENERIC",
        "name": "Generic PHP/ASP WebShell Signature",
        "severity": "CRITICAL",
        "patterns": [
            rb"eval\s*\(\s*base64_decode\s*\(",
            rb"system\s*\(\s*\$_GET",
            rb"passthru\s*\(\s*\$_POST",
            rb"shell_exec\s*\("
        ]
    },
    {
        "id": "RULE_RANSOMWARE_NOTE",
        "name": "Ransomware Ransom Note Signature",
        "severity": "CRITICAL",
        "patterns": [
            rb"YOUR_FILES_ARE_ENCRYPTED",
            rb"all your files have been encrypted",
            rb"HOW_TO_DECRYPT_FILES"
        ]
    },
    {
        "id": "RULE_SUSPICIOUS_POWERSHELL",
        "name": "Encoded PowerShell One-Liner Execution",
        "severity": "HIGH",
        "patterns": [
            rb"powershell(\.exe)?\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
            rb"Invoke-Expression\s*\(New-Object\s+Net\.WebClient\)"
        ]
    }
]

class YaraPatternScanner:
    """
    Scans files and process command lines against YARA-style signature patterns.
    """

    def __init__(self, custom_rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = custom_rules if custom_rules is not None else DEFAULT_RULES

    def scan_bytes(self, content: bytes) -> List[Dict[str, Any]]:
        matches = []
        for rule in self.rules:
            for pattern in rule.get("patterns", []):
                if re.search(pattern, content, re.IGNORECASE):
                    matches.append({
                        "rule_id": rule.get("id"),
                        "rule_name": rule.get("name"),
                        "severity": rule.get("severity", "HIGH"),
                        "matched_pattern": pattern.decode("utf-8", errors="ignore")
                    })
                    break
        return matches

    def scan_file(self, file_path: str, max_bytes: int = 10 * 1024 * 1024) -> List[Dict[str, Any]]:
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return []
        try:
            with open(file_path, "rb") as f:
                content = f.read(max_bytes)
                return self.scan_bytes(content)
        except Exception:
            return []

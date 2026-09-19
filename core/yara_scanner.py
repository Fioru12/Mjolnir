"""
Mjolnir - Real YARA signature scanning, via the `yara-python` bindings to
the actual YARA engine (not a hand-rolled regex approximation).

Compiles every *.yar file found in the rules directory (default:
Mjolnir/rules/, a small honest starter set - see rules/default.yar) and
scans file bytes against them. Because it's real YARA, you can drop in
any public community ruleset (e.g. Yara-Rules/rules, Neo23x0/signature-
base) and it's picked up automatically - no code changes needed.
"""

import glob
import os
from typing import Any, Dict, List, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when the optional
    # dependency truly isn't installed; covered by test_yara_missing_dependency.
    yara = None
    YARA_AVAILABLE = False

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


class YaraRulesNotFoundError(RuntimeError):
    """Raised when no *.yar files exist in the configured rules directory."""


class YaraPatternScanner:
    """
    Scans files against real YARA rules compiled from a directory of *.yar
    files.

    Requires the `yara-python` package (bindings to the compiled libyara
    engine). If it isn't installed, __init__ raises a clear RuntimeError
    immediately rather than silently falling back to something that looks
    like YARA scanning but isn't - that was the previous, misleading
    behaviour this class replaces.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        if not YARA_AVAILABLE:
            raise RuntimeError(
                "yara-python is not installed. Install it with: "
                "pip install yara-python"
            )
        self.rules_dir = rules_dir or DEFAULT_RULES_DIR
        self._rules = self._compile_rules(self.rules_dir)

    @staticmethod
    def _compile_rules(rules_dir: str):
        yar_files = sorted(glob.glob(os.path.join(rules_dir, "*.yar")))
        if not yar_files:
            raise YaraRulesNotFoundError(
                f"No .yar rule files found in {rules_dir}. Add at least one "
                f"(e.g. rules/default.yar, or drop in a public ruleset)."
            )
        # yara.compile requires unique namespace keys per file when passing
        # multiple filepaths; the actual key names don't matter, only that
        # rule names stay unique across files (YARA itself enforces that).
        filepaths = {f"ns_{i}": path for i, path in enumerate(yar_files)}
        return yara.compile(filepaths=filepaths)

    def scan_bytes(self, content: bytes) -> List[Dict[str, Any]]:
        """Scan raw bytes against the compiled rules. Returns a list of
        {rule_id, rule_name, severity, matched_pattern} dicts, one per
        matching rule (not per matched string within a rule)."""
        matches = []
        for m in self._rules.match(data=content):
            meta = m.meta or {}
            matched_identifiers = ", ".join(s.identifier for s in m.strings)
            matches.append({
                "rule_id": m.rule,
                "rule_name": meta.get("description", m.rule),
                "severity": meta.get("severity", "HIGH"),
                "matched_pattern": matched_identifiers,
            })
        return matches

    def scan_file(self, file_path: str, max_bytes: int = 10 * 1024 * 1024) -> List[Dict[str, Any]]:
        """Scan a file on disk. Returns [] (not an exception) for a missing
        file, a directory, or any I/O error - callers already treat an
        empty result as "nothing to report", so this stays consistent with
        the rest of Mjolnir's triage pipeline instead of crashing a triage
        run over one unreadable file."""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return []
        try:
            with open(file_path, "rb") as f:
                content = f.read(max_bytes)
            return self.scan_bytes(content)
        except Exception:
            return []

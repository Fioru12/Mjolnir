import json
import os
import time
from typing import Any, Dict, Optional

# Only these VT result statuses represent a real, verified answer from
# VirusTotal. Transient failures (rate_limited/error) must never be cached,
# otherwise a temporary hiccup would be "frozen" as the answer for the
# entire TTL window (default 24h).
CACHEABLE_STATUSES = {"clean", "malicious", "not_found"}


class VTCache:
    """
    Simple JSON-file-backed cache for VirusTotal hash lookup results.

    Keyed by file hash, storing the raw VT result plus the timestamp it was
    checked at. Entries older than `ttl_hours` are treated as expired and
    are re-checked against the live API.

    This exists to avoid burning through VirusTotal's free-tier quota
    (4 requests/minute) by re-checking the same hash across multiple
    triage runs.
    """

    DEFAULT_CACHE_PATH = ".vt_cache.json"
    DEFAULT_TTL_HOURS = 24

    def __init__(self, cache_path: Optional[str] = None, ttl_hours: float = DEFAULT_TTL_HOURS):
        self.cache_path = cache_path or self.DEFAULT_CACHE_PATH
        self.ttl_hours = ttl_hours if ttl_hours and ttl_hours > 0 else self.DEFAULT_TTL_HOURS
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.cache_path):
            self._data = {}
            return
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self._data = loaded if isinstance(loaded, dict) else {}
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable cache file: start fresh rather than crash.
            self._data = {}

    def _save(self) -> None:
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except OSError:
            # Caching is a best-effort optimization; failure to persist
            # should never break the triage run.
            pass

    def get(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Return the cached VT result for file_hash if present and not expired."""
        entry = self._data.get(file_hash)
        if not entry:
            return None
        checked_at = entry.get("checked_at")
        if checked_at is None:
            return None
        age_hours = (time.time() - checked_at) / 3600.0
        if age_hours > self.ttl_hours:
            return None
        return entry.get("result")

    def set(self, file_hash: str, result: Dict[str, Any]) -> None:
        """Cache a VT result for file_hash, only if it represents a verified status."""
        if not result or result.get("status") not in CACHEABLE_STATUSES:
            return
        self._data[file_hash] = {
            "result": result,
            "checked_at": time.time(),
        }
        self._save()

import hashlib
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from core.vt_cache import VTCache

class VirusTotalScanner:
    """
    Checks file hashes against the VirusTotal API to determine if
    processes found during triage are known malware.
    """

    API_BASE = "https://www.virustotal.com/api/v3"

    # Max attempts (including the first) when VirusTotal responds with
    # HTTP 429 (rate limited).
    MAX_RETRIES = 3
    # Base delay (seconds) for the retry backoff; grows linearly per attempt.
    RETRY_BACKOFF_SECONDS = 2

    def __init__(self, api_key: str = "", requests_per_minute: int = 4,
                 cache: Optional[VTCache] = None, cache_ttl_hours: float = VTCache.DEFAULT_TTL_HOURS,
                 cache_path: Optional[str] = None):
        self.api_key = api_key
        self.enabled = bool(api_key)
        # VirusTotal's free tier allows 4 requests/minute by default.
        self.requests_per_minute = max(1, int(requests_per_minute or 4))
        self._min_interval = 60.0 / self.requests_per_minute
        self._last_request_time: Optional[float] = None
        # Cache VT lookups by hash so repeated triage runs don't re-spend
        # the (very limited) free-tier quota on hashes already checked.
        self.cache = cache if cache is not None else VTCache(cache_path=cache_path, ttl_hours=cache_ttl_hours)

    def _wait_for_rate_limit(self) -> None:
        """Block just long enough to respect requests_per_minute."""
        if self._last_request_time is None:
            return
        elapsed = time.monotonic() - self._last_request_time
        remaining = self._min_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        cached = self.cache.get(file_hash)
        if cached is not None:
            return cached

        result = self._check_hash_live(file_hash)
        if result is not None:
            # Only verified statuses get cached; rate_limited/error results
            # are intentionally excluded (see core.vt_cache.CACHEABLE_STATUSES)
            # so a transient failure isn't "frozen" as the answer for the TTL.
            self.cache.set(file_hash, result)
        return result

    def _check_hash_live(self, file_hash: str) -> Optional[Dict[str, Any]]:
        url = f"{self.API_BASE}/files/{file_hash}"
        req = urllib.request.Request(url, headers={"x-apikey": self.api_key})

        attempt = 0
        while attempt < self.MAX_RETRIES:
            attempt += 1
            self._wait_for_rate_limit()
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    self._last_request_time = time.monotonic()
                    data = json.loads(resp.read().decode())
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})

                    return {
                        "hash": file_hash,
                        "status": "clean" if stats.get("malicious", 0) == 0 and stats.get("suspicious", 0) == 0 else "malicious",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "file_type": attrs.get("type_description", "unknown"),
                        "file_size": attrs.get("size", 0),
                        "reputation": attrs.get("reputation", 0)
                    }
            except urllib.error.HTTPError as e:
                self._last_request_time = time.monotonic()
                if e.code == 404:
                    return {
                        "hash": file_hash,
                        "status": "not_found",
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0,
                    }
                if e.code == 429:
                    if attempt < self.MAX_RETRIES:
                        time.sleep(self.RETRY_BACKOFF_SECONDS * attempt)
                        continue
                    # Exhausted retries: never claim "clean" for a hash we
                    # were unable to verify.
                    return {"hash": file_hash, "status": "rate_limited", "error": str(e)}
                return {"hash": file_hash, "status": "error", "error": str(e)}
            except Exception as e:
                self._last_request_time = time.monotonic()
                return {"hash": file_hash, "status": "error", "error": str(e)}

        # Should not normally be reached, but guard against falling through
        # the loop without a return.
        return {"hash": file_hash, "status": "rate_limited"}

    def compute_hash(self, file_path: str) -> Optional[str]:
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (FileNotFoundError, PermissionError):
            return None

    def scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        file_hash = self.compute_hash(file_path)
        if file_hash:
            return self.check_hash(file_hash)
        return None

    def scan_triage_results(self, triage_data: Dict[str, Any]) -> list:
        results = []
        for proc in triage_data.get("processes", []):
            exe_path = proc.get("exe")
            if exe_path:
                result = self.scan_file(exe_path)
                if result and result.get("status") == "malicious" and result.get("malicious", 0) > 0:
                    results.append({
                        "process": proc.get("name"),
                        "pid": proc.get("pid"),
                        "path": exe_path,
                        "vt_result": result
                    })
        return results

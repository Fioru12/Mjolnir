import hashlib
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

class VirusTotalScanner:
    """
    Checks file hashes against the VirusTotal API to determine if
    processes found during triage are known malware.
    """

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.enabled = bool(api_key)

    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        try:
            url = f"{self.API_BASE}/files/{file_hash}"
            req = urllib.request.Request(url, headers={"x-apikey": self.api_key})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "hash": file_hash,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "file_type": attrs.get("type_description", "unknown"),
                    "file_size": attrs.get("size", 0),
                    "reputation": attrs.get("reputation", 0)
                }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"hash": file_hash, "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "status": "not_found"}
            return None
        except Exception:
            return None

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
                if result and result.get("malicious", 0) > 0:
                    results.append({
                        "process": proc.get("name"),
                        "pid": proc.get("pid"),
                        "path": exe_path,
                        "vt_result": result
                    })
        return results

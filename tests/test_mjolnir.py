import pytest
import os
import io
import time
import urllib.error
from unittest.mock import patch, MagicMock
from core.triage import SystemTriage
from core.ioc_scanner import IOCScanner
from core.reporter import IncidentReporter
from core.virustotal import VirusTotalScanner
from core.vt_cache import VTCache
import main

def test_system_triage():
    triage = SystemTriage()
    info = triage.collect_system_info()
    assert "hostname" in info
    assert "os" in info

    procs = triage.collect_processes()
    assert isinstance(procs, list)
    assert len(procs) > 0

def test_ioc_scanner():
    scanner = IOCScanner()
    mock_data = {
        "processes": [
            {"pid": 123, "name": "mimikatz.exe", "exe": "C:\\temp\\mimikatz.exe"}
        ],
        "network_connections": [
            {"remote_address": "203.0.113.50:443", "pid": 123, "status": "ESTABLISHED"}
        ]
    }
    hits = scanner.scan(mock_data)
    assert len(hits) == 2
    severities = [h["severity"] for h in hits]
    assert "HIGH" in severities
    assert "CRITICAL" in severities

def test_incident_reporter():
    reporter = IncidentReporter(output_dir="output")
    mock_triage = {
        "system_info": {"hostname": "testhost", "os": "Windows", "os_release": "10", "timestamp": "2026-07-23 12:00:00"},
        "processes_count": 50,
        "network_connections": []
    }
    mock_hits = [
        {"type": "SUSPICIOUS_PROCESS", "severity": "HIGH", "indicator": "mimikatz.exe", "details": "Found test"}
    ]
    path = reporter.generate_markdown_report(mock_triage, mock_hits)
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Mjolnir Incident Response Report" in content
        assert "testhost" in content
    
    # Cleanup test report
    if os.path.exists(path):
        os.remove(path)


def test_vt_api_key_env_var_takes_precedence(monkeypatch):
    """VT_API_KEY from the environment must win over config.yaml's value."""
    config = {"virustotal": {"api_key": "key-from-config-yaml"}}

    monkeypatch.setenv("VT_API_KEY", "key-from-env")
    assert main.get_vt_api_key(config) == "key-from-env"

    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert main.get_vt_api_key(config) == "key-from-config-yaml"

    # No env var and no config value at all -> empty string, not None.
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert main.get_vt_api_key({}) == ""


def test_virustotal_429_is_not_reported_as_clean():
    """
    A VirusTotal response of HTTP 429 (rate limited) must never be
    interpreted as a clean hash - the hash was never actually verified.
    """
    scanner = VirusTotalScanner(api_key="dummy-key", requests_per_minute=1000)
    # Avoid real sleeping during the retry backoff in this test.
    scanner.RETRY_BACKOFF_SECONDS = 0

    rate_limited_error = urllib.error.HTTPError(
        url="https://www.virustotal.com/api/v3/files/deadbeef",
        code=429,
        msg="Too Many Requests",
        hdrs=None,
        fp=None,
    )

    with patch("urllib.request.urlopen", side_effect=rate_limited_error):
        result = scanner.check_hash("deadbeef")

    assert result is not None
    assert result["status"] != "clean"
    assert result["status"] == "rate_limited"
    assert result.get("malicious", 0) == 0

    # scan_triage_results must not surface a never-verified hash as a hit,
    # nor silently treat it as clean/benign.
    triage_data = {
        "processes": [
            {"pid": 1, "name": "suspicious.exe", "exe": "C:\\Temp\\suspicious.exe"}
        ]
    }
    with patch("urllib.request.urlopen", side_effect=rate_limited_error):
        with patch.object(scanner, "compute_hash", return_value="deadbeef"):
            hits = scanner.scan_triage_results(triage_data)
    assert hits == []


def test_html_report_escapes_process_name_xss():
    """generate_html_report must escape dynamic values (e.g. process names)
    so an attacker-controlled name can't inject a live <script> tag."""
    reporter = IncidentReporter(output_dir="output")
    malicious_name = "<script>alert('xss')</script>"
    mock_triage = {
        "system_info": {
            "hostname": "testhost",
            "os": "Windows",
            "os_release": "10",
            "os_version": "10.0",
            "architecture": "x64",
            "timestamp": "2026-07-23 12:00:00",
        },
        "processes_count": 1,
        "network_connections": [],
    }
    mock_hits = [
        {
            "type": "SUSPICIOUS_PROCESS",
            "severity": "HIGH",
            "indicator": malicious_name,
            "details": malicious_name,
        }
    ]

    filepath = reporter.generate_html_report(mock_triage, mock_hits)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        assert "<script>alert('xss')</script>" not in content
        assert "&lt;script&gt;" in content
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


# ---------------------------------------------------------------------------
# VTCache tests
# ---------------------------------------------------------------------------

def _cache_path(tmp_path):
    return str(tmp_path / ".vt_cache.json")


def test_vt_cache_set_and_get_roundtrip(tmp_path):
    cache = VTCache(cache_path=_cache_path(tmp_path), ttl_hours=24)
    result = {"hash": "abc123", "status": "malicious", "malicious": 5}
    cache.set("abc123", result)

    # A fresh VTCache instance pointed at the same file must see the entry
    # (proves it's actually persisted to disk, not just in-memory).
    reloaded = VTCache(cache_path=_cache_path(tmp_path), ttl_hours=24)
    assert reloaded.get("abc123") == result


def test_vt_cache_expires_after_ttl(tmp_path):
    cache = VTCache(cache_path=_cache_path(tmp_path), ttl_hours=24)
    cache.set("abc123", {"hash": "abc123", "status": "clean"})

    # Force the stored timestamp far enough in the past to be expired.
    cache._data["abc123"]["checked_at"] = time.time() - (25 * 3600)
    assert cache.get("abc123") is None


def test_vt_cache_does_not_store_transient_statuses(tmp_path):
    cache = VTCache(cache_path=_cache_path(tmp_path))
    cache.set("h1", {"hash": "h1", "status": "rate_limited"})
    cache.set("h2", {"hash": "h2", "status": "error"})
    assert cache.get("h1") is None
    assert cache.get("h2") is None

    # But verified statuses do get stored.
    cache.set("h3", {"hash": "h3", "status": "not_found"})
    assert cache.get("h3") is not None


def test_virustotal_check_hash_uses_cache_without_network_call(tmp_path):
    """
    If a hash is already cached and unexpired, check_hash must return the
    cached result without touching urllib.request.urlopen at all - this is
    what actually saves the free-tier quota.
    """
    cache = VTCache(cache_path=_cache_path(tmp_path))
    cached_result = {"hash": "deadbeef", "status": "clean", "malicious": 0}
    cache.set("deadbeef", cached_result)

    scanner = VirusTotalScanner(api_key="dummy-key", cache=cache)

    with patch("urllib.request.urlopen") as mock_urlopen:
        result = scanner.check_hash("deadbeef")

    mock_urlopen.assert_not_called()
    assert result == cached_result


def test_virustotal_check_hash_populates_cache_on_live_lookup(tmp_path):
    """A hash not yet in the cache should hit the network once, then be
    stored so a subsequent lookup does not."""
    cache = VTCache(cache_path=_cache_path(tmp_path))
    scanner = VirusTotalScanner(api_key="dummy-key", cache=cache)

    mock_response = MagicMock()
    mock_response.read.return_value = io.BytesIO(b'{"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5}, "type_description": "PE32", "size": 1024, "reputation": 0}}}').read()
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_response
    mock_cm.__exit__.return_value = False

    with patch("urllib.request.urlopen", return_value=mock_cm) as mock_urlopen:
        result = scanner.check_hash("newhash")
    assert result["status"] == "clean"
    assert mock_urlopen.call_count == 1

    # Second lookup for the same hash must come from the cache - no more
    # network calls.
    with patch("urllib.request.urlopen") as mock_urlopen2:
        result2 = scanner.check_hash("newhash")
    mock_urlopen2.assert_not_called()
    assert result2["status"] == "clean"


# ---------------------------------------------------------------------------
# IOC scanner IPv6/IPv4 parsing tests
# ---------------------------------------------------------------------------

def test_extract_ip_ipv4_with_port():
    assert IOCScanner.extract_ip("203.0.113.50:443") == "203.0.113.50"


def test_extract_ip_bare_ipv4():
    assert IOCScanner.extract_ip("203.0.113.50") == "203.0.113.50"


def test_extract_ip_bracketed_ipv6_with_port():
    assert IOCScanner.extract_ip("[2001:db8::1]:443") == "2001:db8::1"


def test_extract_ip_bare_ipv6_without_port():
    assert IOCScanner.extract_ip("2001:db8::1") == "2001:db8::1"


def test_extract_ip_invalid_falls_back_to_raw():
    assert IOCScanner.extract_ip("not-an-ip:9999") == "not-an-ip:9999"


def test_ioc_scanner_detects_malicious_ipv6_connection():
    scanner = IOCScanner()
    scanner.SUSPICIOUS_IPS = scanner.SUSPICIOUS_IPS | {"2001:db8::dead:beef"}
    mock_data = {
        "processes": [],
        "network_connections": [
            {"remote_address": "[2001:db8::dead:beef]:8443", "pid": 42, "status": "ESTABLISHED"}
        ]
    }
    hits = scanner.scan(mock_data)
    assert len(hits) == 1
    assert hits[0]["type"] == "MALICIOUS_IP_CONNECTION"


# ---------------------------------------------------------------------------
# CPU double-sampling for suspicious PIDs
# ---------------------------------------------------------------------------

def test_refine_cpu_for_suspicious_pids_double_samples_only_flagged():
    triage = SystemTriage()
    processes = [
        {"pid": 1, "name": "normal.exe", "cpu_percent": 0.0},
        {"pid": 2, "name": "mimikatz.exe", "cpu_percent": 0.0},
    ]

    mock_proc = MagicMock()
    mock_proc.cpu_percent.side_effect = [None, 37.5]

    with patch("core.triage.psutil.Process", return_value=mock_proc) as mock_process_cls, \
         patch("core.triage.time.sleep") as mock_sleep:
        result = triage.refine_cpu_for_suspicious_pids(processes, suspicious_pids=[2], delay=0.1)

    # Only the flagged PID triggers psutil.Process(...) / re-sampling.
    mock_process_cls.assert_called_once_with(2)
    mock_sleep.assert_called_once_with(0.1)
    assert mock_proc.cpu_percent.call_count == 2

    refined = {p["pid"]: p["cpu_percent"] for p in result}
    assert refined[1] == 0.0  # untouched, not flagged
    assert refined[2] == 37.5  # re-sampled


def test_refine_cpu_for_suspicious_pids_handles_vanished_process():
    triage = SystemTriage()
    processes = [{"pid": 99, "name": "ghost.exe", "cpu_percent": 0.0}]

    with patch("core.triage.psutil.Process", side_effect=__import__("psutil").NoSuchProcess(99)):
        result = triage.refine_cpu_for_suspicious_pids(processes, suspicious_pids=[99], delay=0)

    # Should not raise, and leaves the original value in place.
    assert result[0]["cpu_percent"] == 0.0


def test_refine_cpu_for_suspicious_pids_noop_when_no_suspicious_pids():
    triage = SystemTriage()
    processes = [{"pid": 1, "name": "normal.exe", "cpu_percent": 0.0}]

    with patch("core.triage.psutil.Process") as mock_process_cls:
        result = triage.refine_cpu_for_suspicious_pids(processes, suspicious_pids=[])

    mock_process_cls.assert_not_called()
    assert result == processes

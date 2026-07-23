import pytest
import os
from core.triage import SystemTriage
from core.ioc_scanner import IOCScanner
from core.reporter import IncidentReporter

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

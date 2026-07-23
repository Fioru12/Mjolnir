# Mjolnir ⚡ (Incident Response & Triage Automation Engine)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Mjolnir** is part of the **Asgard** cybersecurity suite. It is an automated Incident Response (IR) host triage and threat hunting engine built in Python. When security alerts trigger or an endpoint compromise is suspected, Mjolnir rapidly captures live host telemetry, scans active processes and network sockets against known Indicators of Compromise (IOCs), and generates a professional executive Incident Report in Markdown.

Designed as an advanced portfolio project for aspiring **Incident Responders, SOC Tier 2 Analysts, and Security Engineers**.

---

## 🏗️ Architecture & Component Design

```text
Mjolnir/
│
├── core/
│   ├── triage.py      # Captures live host system telemetry (processes, active sockets, OS info)
│   ├── ioc_scanner.py # Scans processes and network connections against known IOCs
│   └── reporter.py    # Generates structured Markdown Incident Response reports
│
├── output/            # Generated executive incident reports
├── tests/             # Automated test suite (pytest)
├── main.py            # CLI entrypoint for live triage and simulation
└── requirements.txt
```

---

## ✨ Key Features

1. **Host Live Triage**: Extracts active processes, PIDs, executable paths, resource usage, and network connection states using `psutil`.
2. **IOC Threat Hunting**: Automatically flags suspicious/malicious process names (`mimikatz.exe`, `nc.exe`, `psexec.exe`, etc.) and malicious remote IP connections.
3. **Automated Report Generation**: Formats findings into a structured, audit-ready Markdown incident report detailing executive summary, IOC hits, and remediation playbooks.

---

## 🚀 Quickstart Guide

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Fioru12/Mjolnir.git
cd Mjolnir
pip install -r requirements.txt
```

### 2. Running Unit Tests

```bash
pytest
```

### 3. Running Live Triage & Simulation

To run triage with simulated threat artifacts (mimikatz process + malicious IP connection):

```bash
python main.py triage --simulate
```

**Sample Output:**
```text
=================================================================
 Mjolnir - Automated Incident Response & Triage Engine
=================================================================
[*] Collecting live host telemetry (processes, network sockets, OS info)...
[!] SIMULATION MODE: Injecting mock IOC process and malicious network connection for testing...
[*] Scanning telemetry against Threat Intelligence IOCs...
[*] Scan complete. Found 2 indicator(s) of compromise.
[*] Generating Executive Incident Response Report...
[SUCCESS] IR Report successfully generated and saved at: output/Incident_Report_DESKTOP-ABC_2026-07-23_12-00-00.md

=================================================================
 SUMMARY OF FINDINGS:
 - [HIGH] SUSPICIOUS_PROCESS: mimikatz.exe
 - [CRITICAL] MALICIOUS_IP_CONNECTION: 203.0.113.50:443
=================================================================
```

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.

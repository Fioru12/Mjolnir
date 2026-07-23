<div align="center">

# MJOLNIR

### Asgard Cybersecurity Suite - Module II

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![psutil](https://img.shields.io/badge/psutil-5.9+-brightgreen?style=for-the-badge)
![CI](https://github.com/Fioru12/Mjolnir/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)

> **Mjolnir** - *Il martello di Thor, che colpisce una volta sola e non manca mai* - e' un motore automatizzato di **Incident Response**.
> Quando un endpoint e' compromesso, Mjolnir cattura lo stato vivo della macchina, caccia gli IOC e genera un report forense formattato.

</div>

---

## Executive Summary

Quando scatta un alert, il tempo e' il nemico numero uno. Mjolnir esegue un triage forense istantaneo per permettere al team di sicurezza di agire con dati concreti invece di supposizioni.

```
   Alert Heimdall / SIEM
          |
          v
   +------------------+
   |  Mjolnir Triage  |  psutil: processi, socket, utenti, OS
   +--------+---------+
            |
            v
   +------------------+
   |   IOC Scanner    |  mimikatz, psexec, netcat, IP malevoli...
   +--------+---------+
            |
            v
   +------------------+
   |  Report Builder  |  Markdown formattato con severity + playbook
   +------------------+
```

---

## Caratteristiche Tecniche

| Modulo | Descrizione |
|:---|:---|
| **System Triage** | Estrazione processi attivi (PID, path, CPU/RAM), connessioni di rete, info OS via psutil |
| **IOC Scanner** | Confronta processi e connessioni remote contro una knowledge base di IOC noti |
| **Report Generator** | Produce un report Markdown con executive summary, severity scoring e playbook di rimedio |
| **Output Colorato** | Terminal output con colori ANSI per leggibilita immediata |

### IOC rilevati per default

**Processi sospetti:** mimikatz.exe - psexec.exe - nc.exe - netcat - ncat - pwdump.exe - procdump.exe - beacon.exe - powershell_ise.exe

**IP malevoli:** 203.0.113.50 - 198.51.100.22 - 185.220.101.5 - 45.33.32.156

---

## Struttura del Progetto

```
Mjolnir/
+-- core/
|   +-- colors.py         ANSI colori per output terminale
|   +-- triage.py         Host live triage (processi, socket, info OS)
|   +-- ioc_scanner.py    Caccia IOC con knowledge base integrata
|   +-- reporter.py       Generatore report Markdown formattati
|
+-- output/               Report generati (executive summary + dettagli)
+-- tests/
|   +-- test_mjolnir.py   3 test pytest
+-- main.py               CLI: triage [--simulate]
+-- SECURITY.md           Security policy
+-- requirements.txt
```

---

## Quickstart

```bash
# Clone e installa
git clone https://github.com/Fioru12/Mjolnir.git
cd Mjolnir
pip install -r requirements.txt

# Esegui i test
pytest tests/ -v

# Triage con artefatti simulati (mimikatz + IP malevolo)
python main.py triage --simulate
```

---

## Demo: Output Terminale

```
=================================================================
 Mjolnir - Automated Incident Response & Triage Engine
=================================================================
[*] Collecting live host telemetry (processes, network sockets, OS info)...
[!] SIMULATION MODE: Injecting mock IOC process and malicious connection...
[*] Scanning telemetry against Threat Intelligence IOCs...
[*] Scan complete. Found 2 indicator(s) of compromise.
[*] Generating Executive Incident Response Report...
[SUCCESS] IR Report saved at: output/Incident_Report_DESKTOP-ABC.md

=================================================================
 SUMMARY OF FINDINGS:
 - [HIGH]     SUSPICIOUS_PROCESS: mimikatz.exe
 - [CRITICAL] MALICIOUS_IP_CONNECTION: 203.0.113.50:443
=================================================================
```

---

## Report Generato

Ogni esecuzione produce un report Markdown strutturato con:

- **Executive Summary** - hostname, OS, severita globale
- **IOC Findings** - elenco dettagliato degli indicatori trovati
- **Host Telemetry** - conteggio processi, connessioni, architettura
- **Remediation Playbook** - azioni consigliate in base alla severita

---

## Suite Asgard

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS - Rilevamento & Active Response | Fatto |
| **Mjolnir** | Incident Response - Triage & Forensics | Fatto |
| **Bifrost** | Network Telemetry - Port Analysis & Encryption | Fatto |

---

<div align="center">

**[Fioru12](https://github.com/Fioru12)** - MIT License

</div>

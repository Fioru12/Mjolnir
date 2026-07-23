<div align="center">

```
    ██╗  ██╗██╗███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
    ██║  ██║██║██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ███████║██║█████╗  ███████╗██║     ██║   ██║██║  ██║█████╗  
    ██╔══██║██║██╔══╝  ╚════██║██║     ██║   ██║██║  ██║██╔══╝  
    ██║  ██║██║███████╗███████║╚██████╗╚██████╔╝██████╔╝███████╗
    ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
```

### **Asgard Cybersecurity Suite** &mdash; Module II

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![psutil](https://img.shields.io/badge/psutil-5.9+-brightgreen?style=flat-square)
![pytest](https://img.shields.io/badge/pytest-7+-0A9EDC?style=flat-square&logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)

<br/>

**Mjolnir** &mdash; *il martello di Thor, che colpisce una volta sola e non manca mai* &mdash; &egrave; un motore automatizzato di **Incident Response** e **Host Triage**.
Quando un endpoint &egrave; compromesso, Mjolnir cattura lo stato vivo della macchina, caccia gli IOC e genera un report forense formattato pronto per il CISO.

</div>

---

## Il problema che risolve

Dopo un alert nel SIEM, un analista SOC deve:
1. **Triage** &mdash; capire cosa gira sulla macchina compromessa
2. **Threat Hunting** &mdash; cercare processi, hash e connessioni malevole
3. **Report** &mdare; documentare tutto per il team e la compliance

Mjolnir automatizza tutti e tre i passi in **un singolo comando**.

```
   Alert Heimdall / SIEM
          │
          ▼
   ┌──────────────────┐
   │  Mjolnir Triage  │  psutil: processi, socket, utenti, OS
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │   IOC Scanner    │  mimikatz, psexec, netcat, IP malevoli...
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │  Report Builder  │  Markdown formattato con severity + playbook
   └──────────────────┘
```

---

## Architettura

<details>
<summary><b>Struttura completa del progetto</b></summary>

```
Mjolnir/
├── core/
│   ├── triage.py         Host live triage (processi, socket, info OS)
│   ├── ioc_scanner.py    Caccia IOC con database regole integrato
│   └── reporter.py       Generatore report Markdown formattati
│
├── output/               Report generati (executive summary + dettagli)
├── tests/                Suite pytest
├── main.py               CLI: triage [--simulate]
├── requirements.txt
└── README.md
```

</details>

---

## Funzionalit&agrave;

| Modulo | Cosa fa |
|:---|:---|
| **System Triage** | Cattura processi attivi (PID, path, CPU/RAM), connessioni di rete, info OS via `psutil` |
| **IOC Scanner** | Confronta processi e connessioni remote contro una knowledge base di IOC noti (processi malevoli + IP blacklisted) |
| **Report Generator** | Produce un report Markdown con executive summary, severity scoring, lista IOC trovati e playbook di rimedio consigliato |

### IOC rilevati per default

**Processi sospetti:**
`mimikatz.exe` &middot; `psexec.exe` &middot; `nc.exe` &middot; `netcat` &middot; `ncat` &middot; `pwdump.exe` &middot; `procdump.exe` &middot; `beacon.exe` &middot; `powershell_ise.exe`

**IP malevoli:**
`203.0.113.50` &middot; `198.51.100.22` &middot; `185.220.101.5` &middot; `45.33.32.156`

---

## Quickstart

```bash
# Clona e installa
git clone https://github.com/Fioru12/Mjolnir.git
cd Mjolnir
pip install -r requirements.txt

# Test
pytest tests/ -v

# Triage con artefatti simulati (mimikatz + IP malevolo)
python main.py triage --simulate
```

### Output della simulazione

```
=================================================================
 Mjolnir - Automated Incident Response & Triage Engine
=================================================================
[*] Collecting live host telemetry...
[!] SIMULATION MODE: Injecting mock IOC process and malicious connection...
[*] Scanning telemetry against Threat Intelligence IOCs...
[*] Scan complete. Found 2 indicator(s) of compromise.
[*] Generating Executive Incident Response Report...
[SUCCESS] IR Report saved at: output/Incident_Report_HOST_2026-07-23_12-00-00.md

=================================================================
 SUMMARY:
 - [HIGH]     SUSPICIOUS_PROCESS: mimikatz.exe
 - [CRITICAL] MALICIOUS_IP_CONNECTION: 203.0.113.50:443
=================================================================
```

---

## Report generato

Ogni esecuzione produce un report Markdown strutturato con:

- **Executive Summary** &mdash; hostname, OS, severit&agrave; globale
- **IOC Findings** &mdash; elenco dettagliato degli indicatori trovati
- **Host Telemetry** &mdash; conteggio processi, connessioni, architettura
- **Remediation Playbook** &mdash; azioni consigliate in base alla severit&agrave;

---

## Suite Asgard

Mjolnir &egrave; il secondo modulo della **suite Asgard**:

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS &middot; Rilevamento & Active Response | `Fatto` |
| **Mjolnir** | Incident Response &middot; Triage & Forensics | `Fatto` |
| **Bifrost** | Network Telemetry &middot; Crittografia & Port Analysis | `In arrivo` |

---

<div align="center">

*Costruito come progetto portfolio dimostrativo &mdash; pronto per essere mostrato ai recruiter e ai technical lead.*

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License

</div>

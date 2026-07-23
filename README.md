<div align="center">

# ⚡ Mjolnir
### *Automated Incident Response & Host Triage*

[![CI](https://github.com/Fioru12/Mjolnir/actions/workflows/pytest.yml/badge.svg)](https://github.com/Fioru12/Mjolnir/actions/workflows/pytest.yml)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

<br/>

**Mjolnir** è il modulo di *Incident Response* della suite **Asgard**. 
Automatizza la raccolta di prove digitali su host compromessi, scansiona IOC (Indicatori di Compromesso) e genera report forensi pronti per l'analisi.

</div>

---

### 🧠 Executive Summary
Quando scatta un alert, il tempo è il nemico numero uno. **Mjolnir** esegue un triage forense istantaneo per permettere al team di sicurezza di agire con dati concreti invece di supposizioni.

> [!TIP]
> **Mjolnir** analizza in pochi secondi: Processi, Socket di Rete, Utenti e Artefatti di sistema.

---

### 🚀 Funzionalit&agrave; Principali

| Modulo | Obiettivo | Output |
|:---|:---|:---|
| 🔍 **Live Triage** | Estrazione telemetria host | JSON strutturato |
| 🛡️ **IOC Hunting** | Scansione automatica (mimikatz, IP, etc) | Alert Severità |
| 📄 **IR Report** | Generazione report forense automatico | Markdown Auditable |

---

### ⚙️ Demo in Modalit&agrave; Simulazione

```bash
# Esegui il triage simulando un attacco
python main.py triage --simulate
```

**Cosa vedrai nel terminale:**

```text
[*] Collecting live host telemetry...
[!] SIMULATION: Injecting mock IOC process (mimikatz.exe)...
[*] Scan complete. Found 2 indicator(s) of compromise.
[*] Generating Executive Incident Response Report...
[SUCCESS] IR Report saved at: output/Incident_Report_DESKTOP-ABC.md
```

---

<div align="center">

### 🛡️ Suite Asgard
*Un ecosistema integrato per la difesa aziendale.*

| Modulo | Ruolo |
|:---|:---|
| **Heimdall** | HIDS & Active Response |
| **Mjolnir** | Incident Response & Triage |
| **Bifrost** | Network Security & Telemetry |

---

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License
</div>

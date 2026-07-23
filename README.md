# <div align="center">Mjolnir ⚡</div>
<div align="center">
  <sub><i>Il martello di Thor &mdash; Incident Response & Triage Engine</i></sub>
</div>

<br/>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![psutil](https://img.shields.io/badge/psutil-5.9+-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)
![CI](https://github.com/Fioru12/Mjolnir/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)

</div>

<br/>

> [!IMPORTANT]
> **Mjolnir** è il secondo modulo della **suite Asgard**. 
> Automatizza la fase di **triage post-incidente**, raccogliendo prove digitali e generando report forensi in pochi secondi.

---

## 🧠 Executive Summary
Quando scatta un alert, il tempo è il nemico numero uno. **Mjolnir** fornisce una "fotografia" immediata dell'host compromesso, estraendo processi, connessioni e asset di sistema per permettere al team di sicurezza di agire con dati concreti.

```
  Host Compromesso  ──▶  Live Triage (psutil) ──▶  IOC Scanner (DB)
                                                        │
                                                        ▼
                                                 Report Forense
                                                  (Markdown)
```

---

## 🚀 Funzionalit&agrave;

| Modulo | Cosa fa |
|:---|:---|
| 🔍 **System Triage** | Estrazione processi attivi, socket, utenti e info OS |
| 🛡️ **IOC Scanner** | Caccia automatica a mimikatz, netcat, IP malevoli |
| 📄 **Report Engine** | Generazione report Markdown con severity scoring e playbook |

> [!TIP]
> Mjolnir genera un playbook di rimedio consigliato basato sulla severità dell'incidente rilevato.

---

## 🛠️ Quickstart

```bash
# Installazione
git clone https://github.com/Fioru12/Mjolnir.git
cd Mjolnir
pip install -r requirements.txt

# Test
pytest

# Esegui Triage in modalità simulazione
python main.py triage --simulate
```

---

## 🔗 Suite Asgard

| Modulo | Ruolo | Stato |
|:---|:---|:---:|
| **Heimdall** | HIDS &middot; Rilevamento & Response | `Fatto` |
| **Mjolnir** | IR &middot; Triage & Forensics | `Fatto` |
| **Bifrost** | Rete &middot; Telemetria & Report Cifrati | `Fatto` |

---

<div align="center">

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License

</div>

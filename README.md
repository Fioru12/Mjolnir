<div align="center">

# MJOLNIR

### **Asgard Cybersecurity Suite — Module II**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![psutil](https://img.shields.io/badge/psutil-5.9+-brightgreen?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API_v3-orange?style=for-the-badge&logo=virustotal&logoColor=white)
![CI Pipeline](https://github.com/Fioru12/Mjolnir/actions/workflows/pytest.yml/badge.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Perché ho costruito Mjolnir?**  
> Quando scatta un allarme in un SOC, i primi minuti sono dominati dal caos: aprire il task manager, lanciare `netstat`, cercare se quel processo sospetto ha connessioni aperte verso C2 noti. Mjolnir nasce per automatizzare il triage forense iniziale su un host compromesso. Invece di perdere tempo a raccogliere dati a mano, esegue uno snapshot pulito della macchina, cerca IOC noti, interroga VirusTotal e sputa un report Markdown pronto per essere allegato al ticket di incidente.

---

## Flusso di Analisi

```
   Alert Ricevuto (Heimdall / SIEM)
                  |
                  v
    +---------------------------+
    |     System Triage         |  Cattura processi, socket di rete e info OS via psutil
    +-------------+-------------+
                  |
                  v
    +---------------------------+
    |     IOC & VT Scanner      |  Confronta i processi con la KB locale + API VirusTotal
    +-------------+-------------+
                  |
                  v
    +---------------------------+
    |   Markdown IR Reporter    |  Genera un report esecutivo con severità e playbook
    +---------------------------+
```

---

## Scelte Architetturali

- **Leggero e Portabile**: Sfrutta `psutil` per raccogliere informazioni a basso livello sul sistema operativo senza richiedere l'installazione di agenti invasivi.
- **VirusTotal Integration**: Se configurato con una chiave API (anche free), calcola l'hash SHA-256 dei eseguibili sospetti e verifica il tasso di rilevamento dei vari motori AV.
- **Simulation Mode**: Include una modalità di simulazione (`--simulate`) che inietta artefatti malevoli mock (come `mimikatz.exe`) per testare il corretto funzionamento dello scanner e del report builder in ambienti sicuri.

---

## Quick Start

```bash
# Clona e installa
git clone https://github.com/Fioru12/Mjolnir.git
cd Mjolnir
pip install -r requirements.txt

# Esegui il triage in modalità simulazione con controllo VirusTotal
python main.py triage --simulate

# Esegui i test unitari
pytest -v
```

---

<div align="center">

**Sviluppato da [Fioru12](https://github.com/Fioru12)** — Parte della Suite Asgard.

</div>

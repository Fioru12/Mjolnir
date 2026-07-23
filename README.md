<div align="center">

<pre>
   ███╗   ███╗     ██╗ ██████╗ ██╗     ██╗██████╗ 
   ████╗ ████║     ██║██╔═══██╗██║     ██║██╔══██╗
   ██╔████╔██║     ██║██║   ██║██║     ██║██████╔╝
   ██║╚██╔╝██║██   ██║██║   ██║██║     ██║██╔══██╗
   ██║ ╚═╝ ██║╚█████╔╝╚██████╔╝███████╗██║██║  ██║
   ╚═╝     ╚═╝ ╚════╝  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝
</pre>

`>>> mjolnir.exe --init --suite=asgard`

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![CI](https://github.com/Fioru12/Mjolnir/actions/workflows/pytest.yml/badge.svg?style=flat&logo=github)
![Status](https://img.shields.io/badge/SYSTEM-OPERATIONAL-00FF00?style=flat&logo=hackthebox)

---

### 📟 SYSTEM CORE
**Mjolnir** è il modulo di *Automated Triage & Forensics* della suite **Asgard**. 
Non aspettare l'analista: **estrai, scansiona, documenta**.

</div>

---

### ⚡ TACTICAL DASHBOARD
<pre>
[✓] HOST TRIAGE    : psutil-based live memory/socket snapshot
[✓] IOC HUNTING    : Automated scan (mimikatz, nc, psexec)
[✓] IR REPORTING   : Markdown Forensics Playbook ready
</pre>

---

### 🛠️ LIVE SIMULATION
```bash
python main.py triage --simulate
```

<details>
<summary><b>> Visualizza Output Terminale</b></summary>

```text
[*] Collecting live host telemetry...
[!] SIMULATION: Injecting mock IOC process (mimikatz.exe)...
[*] Scan complete. Found 2 indicator(s) of compromise.
[*] Generating Executive Incident Response Report...
[SUCCESS] IR Report saved at: output/Incident_Report_DESKTOP-ABC.md

SUMMARY OF FINDINGS:
 - [HIGH]     SUSPICIOUS_PROCESS: mimikatz.exe
 - [CRITICAL] MALICIOUS_IP_CONNECTION: 203.0.113.50:443
```
</details>

---

### 🛡️ ASGARD SUITE
| Module | Role |
|:---|:---|
| 🛡️ **Heimdall** | HIDS / Detection |
| ⚡ **Mjolnir** | IR / Triage |
| 🌈 **Bifrost** | Network / Telemetry |

<div align="center">

**[Fioru12](https://github.com/Fioru12)** &middot; MIT License
</div>

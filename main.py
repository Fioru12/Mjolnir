import sys
import argparse
import yaml
from core.triage import SystemTriage
from core.ioc_scanner import IOCScanner
from core.reporter import IncidentReporter
from core.virustotal import VirusTotalScanner
from core.colors import Colors

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def load_config():
    try:
        with open("config.yaml", "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}

def run_triage(simulate: bool = False, check_vt: bool = False):
    print(Colors.FAIL + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Mjolnir - Automated Incident Response & Triage Engine{Colors.ENDC}")
    print(Colors.FAIL + "=" * 65 + Colors.ENDC)

    config = load_config()
    triage = SystemTriage()
    scanner = IOCScanner()
    reporter = IncidentReporter()

    vt_key = config.get("virustotal", {}).get("api_key", "")
    vt = VirusTotalScanner(api_key=vt_key)

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Collecting live host telemetry (processes, network sockets, OS info)...")
    triage_data = triage.run_full_triage()

    if simulate:
        print(f"{Colors.WARNING}[!]{Colors.ENDC} SIMULATION MODE: Injecting mock IOC process and malicious network connection for testing...")
        triage_data["processes"].append({
            "pid": 9999,
            "name": "mimikatz.exe",
            "exe": "C:\\Temp\\mimikatz.exe",
            "username": "Administrator",
            "cpu_percent": 15.0,
            "memory_percent": 3.4
        })
        triage_data["network_connections"].append({
            "fd": 10,
            "family": "AddressFamily.AF_INET",
            "type": "SocketKind.SOCK_STREAM",
            "local_address": "192.168.1.100:54321",
            "remote_address": "203.0.113.50:443",
            "status": "ESTABLISHED",
            "pid": 9999
        })
        triage_data["processes_count"] = len(triage_data["processes"])

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Scanning telemetry against Threat Intelligence IOCs...")
    ioc_hits = scanner.scan(triage_data)
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Scan complete. Found {Colors.BOLD}{len(ioc_hits)}{Colors.ENDC} indicator(s) of compromise.")

    vt_hits = []
    if check_vt:
        if vt.enabled:
            print(f"{Colors.CYAN}[*]{Colors.ENDC} Running VirusTotal hash check on triaged processes...")
            vt_hits = vt.scan_triage_results(triage_data)
            if vt_hits:
                for hit in vt_hits:
                    det = hit["vt_result"]
                    print(f"   {Colors.FAIL}[MALWARE]{Colors.ENDC} {hit['process']} (PID {hit['pid']}) -> {det['malicious']}/{det['malicious']+det.get('harmless',0)+det.get('undetected',0)} engines detected")
            else:
                print(f"   {Colors.GREEN}[CLEAN]{Colors.ENDC} No known malware found in triaged processes.")
        else:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} VirusTotal API key not configured. Skipping VT check.")

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Generating Executive Incident Response Report...")
    report_path = reporter.generate_markdown_report(triage_data, ioc_hits + [{"type": "VT", "indicator": h["process"], "severity": "CRITICAL", "detail": f"{h['vt_result']['malicious']} engines"} for h in vt_hits])
    print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} IR Report saved at: {report_path}")

    print("\n" + Colors.FAIL + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} SUMMARY OF FINDINGS:{Colors.ENDC}")
    for hit in ioc_hits:
        sev_color = Colors.FAIL if hit['severity'] == 'CRITICAL' else Colors.WARNING
        print(f" - {sev_color}[{hit['severity']}]{Colors.ENDC} {hit['type']}: {hit['indicator']}")
    for hit in vt_hits:
        print(f" - {Colors.FAIL}[CRITICAL]{Colors.ENDC} VT: {hit['process']} ({hit['vt_result']['malicious']} detections)")
    print(Colors.FAIL + "=" * 65 + Colors.ENDC)

def main():
    parser = argparse.ArgumentParser(description="Mjolnir: Automated Incident Response Triage Engine")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    triage_parser = subparsers.add_parser("triage", help="Run live host triage and IR report generation")
    triage_parser.add_argument("--simulate", action="store_true", help="Inject mock malicious artifacts for testing")
    triage_parser.add_argument("--vt", action="store_true", help="Check process hashes against VirusTotal API")

    args = parser.parse_args()

    if args.command == "triage":
        run_triage(simulate=args.simulate, check_vt=args.vt)
    else:
        run_triage(simulate=True, check_vt=False)

if __name__ == "__main__":
    main()
